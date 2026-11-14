# Running the attack simulation

Companion to [`attack-types.md`](./attack-types.md) (what each attack is and which
layer it hits) and [`requirement.md`](./requirement.md) (the capture/labeling contract).
This page is about `ai-model/05_run_attacks.sh` — the one command that runs the attacks
against **your own** local cluster and produces a complete, labeled capture session.

> **Safety.** For your own minikube cluster only. The floods can disrupt the demo;
> they are **bounded-safe by default** so the single node survives, and `--intense`
> unlocks full force. Every attack is time-bounded and teardown always runs.

## What it does, in one run

1. Snapshots pod IPs (`01_snapshot_pods.sh`).
2. Starts L7 access-log streaming (`02_stream_logs.sh`) and the L3/4 packet capture
   (`03_capture_pcap.sh start`).
3. Deploys an **unmeshed attacker pod** (`attacker-pod.yaml`) with the attack tools.
4. Runs the selected attacks, one at a time, each in its own window with a clean
   normal-traffic gap between them, repeated for `--rounds` so every class lands across
   the session (helps the model's temporal train/val/test split).
5. Writes `labels.csv` automatically. Every row carries `source_ip=<attacker pod IP>`
   (so `04_pcap_to_flows.sh` tags **only the attacker's own flows**, not normal background
   in the window), and L7 attacks **also** carry `match_ua=atk-<label>` — a per-attack
   `User-Agent` that `build_dataset.py` keys the L7 label on (exact attacker requests, not fan-out).
   Each attack's stdout/stderr goes to `attacks/r<round>_<attack>.log`; a window that ends
   far short of `--dur` prints a `WARN` and gets a `short` note.
6. Stops + fetches the pcaps, kills the log stream, deletes the attacker pod.
7. Prints the exact `build_dataset.py` / `04_pcap_to_flows.sh` commands for the session.

Everything lands in a timestamped `ai-model/session_<split>_<UTC>/` directory: `logs/`,
`pcaps/`, `attacks/`, `pods_*.json`, `split.txt`, and `labels.csv`.

## Train / validation / test: three separate sessions

The model splits were previously one session cut 60/20/20 by time, so whichever classes
happened to fall in the last 20% were the only ones tested — and validation (which picks
the best epoch) could miss classes entirely. Capture **three independent sessions** instead,
each class-complete, with `--split`:

```sh
./05_run_attacks.sh --split train --rounds 2 --build   # most data
./05_run_attacks.sh --split val   --rounds 1 --build   # its own validation data
./05_run_attacks.sh --split test  --rounds 1 --build   # its own held-out test data
.venv/bin/python two_view_hetero_gat.py \
    --netflows      session_train_<UTC>/dataset/netflows.csv \
    --graphml       session_train_<UTC>/dataset/observed_services.graphml \
    --val_netflows  session_val_<UTC>/dataset/netflows.csv \
    --test_netflows session_test_<UTC>/dataset/netflows.csv \
    --explain       session_test_<UTC>/explain
```

The featurisation (numeric scaling, proto/state levels, port→service mapping, class list)
is fit on the **training** session only and reused on val/test, and each split is its own
graph, so test flows never leak into training. The training session's `observed_services.graphml`
is used for every split (the app topology is the same across sessions).

## Prerequisites

```sh
# 1) Istio + logging + ingress, then deploy the app + baseline loadgen.
#    skaffold.yaml is at the repo ROOT, so run skaffold from there (NOT from ai-model/).
cd <repo-root>                       # e.g. cd ~/Documents/final-thesis/microservices-demo
./ai-model/00_setup_istio.sh         # idempotent; safe to re-run
skaffold run                         # SKIP if the app is already deployed (kubectl get pods)
#   if pods predate Istio and lack a sidecar:  ./ai-model/00_setup_istio.sh --restart-app

# 2) Build the attack + flow-extraction images (run these from ai-model/).
cd ai-model
docker build -f Dockerfile.attacker  -t attacker:local  .
docker build -f Dockerfile.flowtools -t flowtools:local .   # for the L3/4 build step
```

> If `skaffold run` says *"skaffold.yaml not found"*, you're in `ai-model/` — `cd` to
> the repo root. And if `kubectl get pods -n default` already shows the app `2/2`
> Running, you can skip `skaffold run` entirely.

## Usage

```sh
./05_run_attacks.sh                      # full suite, 2 rounds, bounded-safe (capture only)
./05_run_attacks.sh --train              # ONE COMMAND: capture -> dataset -> train
./05_run_attacks.sh --build              # capture -> dataset (no training)
./05_run_attacks.sh --train --sweep      # ...and run the full comparison table
./05_run_attacks.sh --dry-run --train    # print every command + the pipeline, run nothing
./05_run_attacks.sh --only brute_force,http_flood --rounds 1
./05_run_attacks.sh --no-l34             # L7 application attacks only (skip raw floods)
./05_run_attacks.sh --intense            # full-force floods (can crash a 1-node cluster)
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--split train\|val\|test` | train | role of this session; names the dir `session_<split>_<UTC>` |
| `--rounds N` | 2 | how many times to cycle the suite (spreads each class over time) |
| `--dur S` | 30 | seconds per attack |
| `--gap S` | 45 | seconds of clean normal traffic between attacks |
| `--min_flows N` | 50 | warn if a selected attack yields fewer labeled flows (the "enough data?" check) |
| `--only a,b` | — | run only these attacks |
| `--skip a,b` | — | run all but these |
| `--no-l34` | off | skip the raw-socket L4/L3 floods (SYN/UDP/ICMP/conn + scan) |
| `--intense` | off | full-force floods instead of bounded-safe |
| `--build` | off | after the session, build the dataset (`build_dataset.py` + `04_pcap_to_flows.sh`) using the venv |
| `--train` | off | `--build` **and** train (`two_view_hetero_gat.py`); needs the venv + `flowtools:local` + torch |
| `--sweep` | off | with `--train`, run the full comparison table |
| `--dry-run` | off | print commands + label rows (and the pipeline it would run), execute nothing |
| `--out DIR` | `session_<UTC>` | session output directory |

**One-command pipeline:** `--build`/`--train` run `build_dataset.py`,
`04_pcap_to_flows.sh` and (with `--train`) `two_view_hetero_gat.py` automatically, using
`ai-model/.venv/bin/python` — so you don't hit the system-Python `ModuleNotFoundError`.
Prerequisites are checked **before** the capture (venv, `flowtools:local`, torch), so a
missing dep fails fast instead of after a long session. A build/train failure never
deletes the captured session.

Attack names: `http_flood`, `http_flood_low`, `fuzzing`, `injection`, `brute_force`,
`malformed_http`, `slow_http`, `port_scan`, `conn_flood`, `syn_flood`, `udp_flood`,
`icmp_flood` (see `attack-types.md` for each). `http_flood_low` is a deliberately
low-rate pass labeled `http_flood`, so the model can't just threshold on volume.

## Targets

- **L7** attacks hit the ingress gateway Service
  (`istio-ingressgateway.istio-system:80`), so traffic flows gateway → frontend and
  `/login` → authservice — the same path as a real external client.
- **L4/L3** attacks target a backend **pod IP** (frontend), so the bridge pcap records
  real attacker→target packets.

## After a session: build the dataset

The script prints these with the real paths filled in. **Use the venv's Python**
(`.venv/bin/python`) — the system Python has no pandas/networkx/torch; run from
`ai-model/`:

```sh
# (one-time) create the venv + deps:  python3 -m venv .venv && .venv/bin/pip install -r requirements-model.txt
.venv/bin/python build_dataset.py --logs session_<UTC>/logs --pods "session_<UTC>/pods_*.json" \
    --labels session_<UTC>/labels.csv --out_dir session_<UTC>/dataset
./04_pcap_to_flows.sh session_<UTC>/pcaps session_<UTC>/labels.csv session_<UTC>/dataset/netflows.csv
.venv/bin/python two_view_hetero_gat.py \
    --netflows session_<UTC>/dataset/netflows.csv --graphml session_<UTC>/dataset/observed_services.graphml
```

> `ModuleNotFoundError: No module named 'networkx'` means you used the system Python —
> prefix with `.venv/bin/python` (or `source .venv/bin/activate` first). `04_pcap_to_flows.sh`
> uses only stdlib + docker, so it doesn't need the venv.

## Notes

- **`slow_http` and the L4/L3 attacks need verification/the pcap** to be meaningful —
  `slow_http` may be buffered by Envoy (`attack-types.md §6`), and SYN/UDP/ICMP/connect
  floods are invisible to Istio and only show up in `netflows.csv` (`attack-types.md §7–10`).
- **Review before running for real:** `--dry-run` prints every exact command and the
  label rows, so you can audit the session without touching the cluster.
- **Baseline matters:** leave the demo `loadgenerator` running so the gaps are real
  normal traffic; the script does not stop it.
- **Check `attacks/*.log` and the WARN lines.** If an attack ends in well under `--dur`
  (a `short` note in `labels.csv`, or a `WARN:` line), the tool failed — read its log and
  re-run. After `--build`, the script also prints per-class netflow counts and warns about
  any class under `--min_flows`.
- **Recapture needed for old sessions:** sessions captured before this fix have **no** L3/4
  attack flows (nmap/hping3 ran with an unset target and exited instantly) and over-broad
  L3/4 labels (UA attacks wrote a blank `source_ip`, so every flow in the window was tagged).
  Re-run the three `--split` sessions above to get a clean dataset.
