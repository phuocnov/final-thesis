# Capturing a labeled dataset from your own Online Boutique + Istio cluster

This replaces the UNSW-NB15 + synthetic-FTGO setup with data from a system you
actually run: real service-to-service calls (L7) and real request/response
stats you can shape into an L3/4-like flow table, both from the **same**
deployment, with a flow→service mapping that's observed instead of invented.

**Prerequisite:** Istio must be installed with JSON access logging, the namespace
labeled for injection, and the ingress gateway applied. None of that comes from
`skaffold run`, and `minikube delete` wipes it — so run the setup script after
creating the cluster and before `skaffold run`. **Run both from the repo ROOT**
(`skaffold.yaml` is there, not in `ai-model/`):
```
cd <repo-root>               # e.g. cd ~/Documents/final-thesis/microservices-demo
./ai-model/00_setup_istio.sh # idempotent; see docs/build_dataset/requirement.md §1
skaffold run                 # deploy the app (now gets sidecars); skip if already deployed
```
Confirm with `kubectl logs deploy/frontend -c istio-proxy --tail=3` showing JSON
lines. If pods predate the setup, re-run `./ai-model/00_setup_istio.sh --restart-app`.
(`skaffold run` from inside `ai-model/` fails with "skaffold.yaml not found" — that's
the wrong directory, not a real error.)

## Quickest path: one-command attack session

If you just want a labeled dataset, `05_run_attacks.sh` does the whole session for you
(snapshot + log streaming + pcap capture + attacks + `labels.csv` + teardown):
```
docker build -f Dockerfile.attacker  -t attacker:local  .
docker build -f Dockerfile.flowtools -t flowtools:local .
./05_run_attacks.sh --dry-run      # review the exact commands first
./05_run_attacks.sh                # full suite, bounded-safe; prints the build commands at the end
./05_run_attacks.sh --train        # ONE command: capture -> build dataset -> train (uses .venv)
```

**Preferred: capture three separate sessions** (train / validation / test), each
class-complete, so the model is validated and tested on data that holds every attack type —
not just whichever classes land in the tail of a single session:
```
./05_run_attacks.sh --split train --rounds 2 --build   # most data
./05_run_attacks.sh --split val   --rounds 1 --build   # its own validation data
./05_run_attacks.sh --split test  --rounds 1 --build   # its own held-out test data
```
Each session lands in `session_<split>_<UTC>/`. Every attack's output is saved under
`attacks/r<round>_<attack>.log`, every `labels.csv` row carries the attacker `source_ip`
(L7 attacks also a `match_ua` tag), and the script prints a `WARN` (and a `short` note) if
an attack ends well under `--dur` — check those before trusting the data. See
[docs/build_dataset/attack-simulation.md](../docs/build_dataset/attack-simulation.md).

The numbered steps below are the manual pipeline it automates (use them for custom runs).

## 1. One-time per session: snapshot pod IPs
```
./01_snapshot_pods.sh
```
Re-run this after any `kubectl rollout restart` or pod reschedule — pod IPs
change and stale snapshots mis-resolve callers/callees. Keep every snapshot
file; `build_dataset.py` takes them all and picks whichever was most recent
as of each log line's timestamp.

## 2. Start log streaming (separate terminal, leave running)
```
./02_stream_logs.sh
```
Writes one file per pod under `logs/`. Stop with Ctrl-C when the whole
session is done.

## 3. Generate traffic and fill in labels.csv
Copy `labels_template.csv` to `labels.csv`. For the "normal" baseline, just
let the demo's own `loadgenerator` run and record its time window.

For attack traffic, run the generation yourself with standard tools
(`hping3`, `slowhttptest`, `nmap`, `wrk2`/Locust at high concurrency, `ffuf`,
OWASP ZAP, or similar) against your own cluster's Istio ingress address.
Use `./mark.sh "<what you're about to run>"` right before and right after
each run to get accurate UTC timestamps without doing date math, and paste
those into `labels.csv`:

```
start_time,end_time,label,source_ip,match_ua,notes
2026-01-01T00:00:00Z,2026-01-01T00:05:00Z,normal,,,loadgenerator baseline
2026-01-01T00:10:00Z,2026-01-01T00:10:30Z,http_flood,,atk-http_flood,ua-tagged attack (set your tool's User-Agent to contain atk-http_flood)
2026-01-01T00:12:00Z,2026-01-01T00:12:30Z,port_scan,10.244.1.99,,in-cluster attacker pod (reliable source_ip)
```

The two label keys (mirror `labels_template.csv`):
- **`match_ua`** — a substring of the attacker's `User-Agent`. `build_dataset.py` tags
  exactly the requests carrying it (the entry request, not fan-out). Best for L7 attacks:
  set your tool's `User-Agent` to contain it.
- **`source_ip`** — the attacker's address. In the pcap (`netflows.csv`) this reliably
  identifies an **in-cluster** sender (pod IPs are unique within a snapshot), so `05_run_attacks.sh`
  runs attacks from an in-cluster attacker pod and records its IP on every row. For traffic
  from outside the cluster, every internal service sees the *gateway's* pod IP instead of the
  real client, so an external `source_ip` can't separate senders — use `match_ua` and a clean
  time window there.

Run each attack in its own window with nothing else generating load (except the baseline
`loadgenerator`), so the labels stay clean. A few minutes of normal traffic between attacks
is worth having too.

## 4. Build the dataset
Install the deps into a venv once (this box's system Python is externally managed, so a bare
`pip install` is blocked), then use that venv's Python:
```
python3 -m venv .venv && .venv/bin/pip install -r requirements-model.txt
.venv/bin/python build_dataset.py --logs logs --pods pods_*.json --labels labels.csv --out_dir dataset
```
Run `.venv/bin/python build_dataset.py --selftest` any time to check the parser still
works (no cluster needed) before trusting it on your real logs.

Output in `dataset/`:
- **`requests.csv`** — one row per request (L7): caller/callee service,
  method, path, response/grpc status, duration, bytes, label.
- **`flows.csv`** — `(caller_ip, callee_pod, time-bucket)` aggregates
  (request count, bytes, duration, error count, majority label).
- **`observed_services.graphml`** — the service-call graph **actually
  observed** in your traffic. Use this in place of the FTGO GraphML:
  `.venv/bin/python two_view_hetero_gat.py --graphml dataset/observed_services.graphml ...`
- **`observed_services_yed.graphml`** — the same graph with yFiles labels, colors and a
  layout, for opening in [yEd](https://www.yworks.com/products/yed) (the plain file shows as
  one unlabeled box there). Convert an existing file with
  `.venv/bin/python build_dataset.py --to_yed dataset/observed_services.graphml`.

## Fixed after reviewing a real sample log line

A real inbound `upstream_cluster` from this cluster looks like
`inbound|8080||;` — no destination service name in it (that's normal: Envoy
doesn't need to name its own service in its own inbound cluster). The
original parser assumed it could read the callee's identity from that
field; it can't, and every row would have resolved to garbage. Fixed: the
destination service now comes from `sa` (the pod's own service account,
already in the log line — Online Boutique sets it equal to the service
name), with the pod-name snapshot lookup as a fallback only if `sa` is
missing. Re-run `python build_dataset.py --selftest` to see this covered
by a regression check.

## Honesty check before you write this up

`flows.csv` is built from the **same** Istio access logs as `requests.csv` —
it's a convenience L3/4-*shaped* aggregate (counts/bytes/duration per
caller↔callee pair per time bucket), not an independent packet capture. The
two views are therefore correlated by construction, which is a weaker setup
than UNSW-NB15 + a truly separate L7 source would have been, and you should
say so explicitly in the thesis rather than imply independence.

What *is* genuinely new and better than before: `observed_services.graphml`
is a real topology from your real traffic, and the flow→service mapping is
resolved from actual pod IPs rather than assigned at random. So the "does
the L7 topology carry information beyond the host view" question is now
being asked of real data, even though the L3/4 features themselves are
derived rather than captured independently.

A genuinely independent L3/4 source now exists — see the next section.

## 5. Independent L3/4 capture (Argus) — the real network-layer view

`flows.csv` above is derived from the same Istio logs as the L7 view. For a
*real*, independent L3/4 view (and to see SYN/UDP/connect-flood attacks Istio
can't), run a packet capture alongside Istio and extract flow features with
**Argus** (the UNSW-NB15 extractor). Full write-up:
[`docs/build_dataset/l3-capture.md`](../docs/build_dataset/l3-capture.md).

```
docker build -f Dockerfile.flowtools -t flowtools:local .   # once
./03_capture_pcap.sh start            # BEFORE traffic; same window as 02_stream_logs.sh
# ... run baseline + attacks (see docs/build_dataset/attack-types.md), mark windows ...
./03_capture_pcap.sh fetch pcaps
./03_capture_pcap.sh stop
./04_pcap_to_flows.sh pcaps labels.csv dataset/netflows.csv
```

Output `dataset/netflows.csv` carries UNSW-style per-flow features
(`dur, sbytes, dbytes, sttl, dttl, swin, dwin, spkts, dpkts, sload, dload,
sloss, dloss, smeansz, dmeansz, sjit, djit, tcprtt, synack, ackdat`, `proto`,
`state`) with real source IPs, labeled from the same `labels.csv`.

## What to do with it

The model trains on captured data only (no UNSW-NB15). Install its deps into a venv first:
`python3 -m venv .venv && .venv/bin/pip install -r requirements-model.txt` (torch needs
Python ≤ 3.13 — see that file).

**One command for all of it:** `./06_build_and_compare.sh` auto-picks the newest
train/val/test sessions, builds any missing `dataset/`, and prints the `l34` / `l7` / `both`
comparison (`--sweep` for the full 7-config table, `--explain` for the per-alert figures).
It defaults to `--max-normal 150000` and honors `--cpu`.

**Preferred: train / validate / test on the three separate sessions** from the
"Quickest path" above, so each split holds every attack class and test data never leaks
into training (the featuriser is fit on the training session and each split is its own graph):
```
.venv/bin/python two_view_hetero_gat.py \
    --netflows      session_train_<UTC>/dataset/netflows.csv \
    --graphml       session_train_<UTC>/dataset/observed_services.graphml \
    --val_netflows  session_val_<UTC>/dataset/netflows.csv \
    --test_netflows session_test_<UTC>/dataset/netflows.csv \
    --max_normal 150000 \   # cap the normal class (keeps ALL attacks): fits a small GPU + eases the ~94% imbalance
    --device cpu \          # optional: run on CPU if the GPU OOMs on large graphs
    --explain       session_test_<UTC>/explain      # per-alert L3/4-vs-L7 attention: CSV + PNGs
```

> **Capture all three splits with the SAME flags** (same `--intense`/bounded, same `--rounds`),
> or train and test come from different traffic distributions and the comparison is invalid.
> The datasets are mostly `normal` (~90%+) and can reach ~1M flows; `--max_normal N` caps the
> normal class per split while keeping every attack flow, and `--device cpu` sidesteps GPU memory limits.

**Single session** (fallback): one `--netflows` with no val/test files splits it 60/20/20 by
time. Simplest, but whichever classes fall in the last 20% are the only ones tested — the
script warns about this.
```
.venv/bin/python two_view_hetero_gat.py \
    --netflows dataset/netflows.csv \
    --graphml  dataset/observed_services.graphml \
    --views both        # or l34 / l7 / none; add --sweep for the full comparison table
```

`netflows.csv` (the real L3/4 view from Argus) supersedes the derived `flows.csv`. The two
views stay separate tables fused in-model via shared host/service nodes.
