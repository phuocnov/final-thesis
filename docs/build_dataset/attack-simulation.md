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
5. Writes `labels.csv` automatically using the entry-point scheme:
   - **L7 attacks** → `match_ua=atk-<label>` (a per-attack `User-Agent` the parser keys
     on — tags exactly the attacker's requests, not fan-out).
   - **L4/L3 + malformed/slow** (no usable UA) → `source_ip=<attacker pod IP>` + time.
6. Stops + fetches the pcaps, kills the log stream, deletes the attacker pod.
7. Prints the exact `build_dataset.py` / `04_pcap_to_flows.sh` commands for the session.

Everything lands in a timestamped `ai-model/session_<UTC>/` directory: `logs/`,
`pcaps/`, `pods_*.json`, and `labels.csv`.

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
./05_run_attacks.sh                      # full suite, 2 rounds, bounded-safe
./05_run_attacks.sh --dry-run            # print every command + the labels rows, run nothing
./05_run_attacks.sh --only brute_force,http_flood --rounds 1
./05_run_attacks.sh --no-l34             # L7 application attacks only (skip raw floods)
./05_run_attacks.sh --intense            # full-force floods (can crash a 1-node cluster)
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--rounds N` | 2 | how many times to cycle the suite (spreads each class over time) |
| `--dur S` | 30 | seconds per attack |
| `--gap S` | 45 | seconds of clean normal traffic between attacks |
| `--only a,b` | — | run only these attacks |
| `--skip a,b` | — | run all but these |
| `--no-l34` | off | skip the raw-socket L4/L3 floods (SYN/UDP/ICMP/conn + scan) |
| `--intense` | off | full-force floods instead of bounded-safe |
| `--dry-run` | off | print commands + label rows, execute nothing |
| `--out DIR` | `session_<UTC>` | session output directory |

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

The script prints these with the real paths filled in:

```sh
python build_dataset.py --logs session_<UTC>/logs --pods "session_<UTC>/pods_*.json" \
    --labels session_<UTC>/labels.csv --out_dir session_<UTC>/dataset
./04_pcap_to_flows.sh session_<UTC>/pcaps/cap session_<UTC>/labels.csv session_<UTC>/dataset/netflows.csv
python two_view_hetero_gat.py \
    --netflows session_<UTC>/dataset/netflows.csv --graphml session_<UTC>/dataset/observed_services.graphml
```

## Notes

- **`slow_http` and the L4/L3 attacks need verification/the pcap** to be meaningful —
  `slow_http` may be buffered by Envoy (`attack-types.md §6`), and SYN/UDP/ICMP/connect
  floods are invisible to Istio and only show up in `netflows.csv` (`attack-types.md §7–10`).
- **Review before running for real:** `--dry-run` prints every exact command and the
  label rows, so you can audit the session without touching the cluster.
- **Baseline matters:** leave the demo `loadgenerator` running so the gaps are real
  normal traffic; the script does not stop it.
