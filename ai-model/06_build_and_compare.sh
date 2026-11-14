#!/usr/bin/env bash
# Build the datasets for the three captured sessions (train / val / test) and compare
# the three GAT views (L3/4, L7, both) on them. A thin orchestrator over the existing
# scripts -- no new logic:
#   build_dataset.py      -> L7 view  (requests.csv, observed_services.graphml)
#   04_pcap_to_flows.sh   -> L3/4 view (netflows.csv, via Argus / flowtools:local)
#   two_view_hetero_gat.py -> train on train, pick epoch on val, report on test
#
# Capture the sessions first (same flags each time):
#   ./05_run_attacks.sh --split train --rounds 2
#   ./05_run_attacks.sh --split val   --rounds 1
#   ./05_run_attacks.sh --split test  --rounds 1
# Then:
#   ./06_build_and_compare.sh                 # build missing datasets + l34/l7/both compare
#   ./06_build_and_compare.sh --sweep         # full 7-config table (adds shuffled/random controls)
#   ./06_build_and_compare.sh --explain       # also write per-alert view attention for the test set
#   ./06_build_and_compare.sh --drop_strong   # drop the sttl/dttl giveaway (harder task)
#   ./06_build_and_compare.sh --rebuild       # rebuild datasets even if they already exist
#   ./06_build_and_compare.sh --max-normal N  # cap the normal class per split (default 150000; 0 = off)
#   ./06_build_and_compare.sh --cpu           # run the model on CPU (avoids GPU OOM on big graphs)
#   ./06_build_and_compare.sh --train-dir session_train_... --val-dir ... --test-dir ...
#
# By default it auto-picks the NEWEST session_{train,val,test}_* directory for each role.
# NOTE: capture train/val/test with the SAME flags (same --intense/bounded, same rounds) or the
# comparison is invalid. --max-normal keeps ALL attack flows and only downsamples normal.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="$HERE/.venv/bin/python"   # the venv has pandas/networkx/torch; system python does not
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True   # reduce CUDA fragmentation; harmless on CPU

# ---- defaults -------------------------------------------------------------------
SEEDS="0,1,2,3,4"
SWEEP=0
EXPLAIN=0
REBUILD=0
DROP=""
MAX_NORMAL=150000   # cap normal flows per split (fits ~3.6 GB GPU after a bounded capture); 0 = off
DEVICE="auto"       # auto|cpu|cuda
TRAIN_DIR=""
VAL_DIR=""
TEST_DIR=""

usage() { sed -n '2,31p' "$0"; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --seeds) SEEDS="$2"; shift 2 ;;
        --sweep) SWEEP=1; shift ;;
        --explain) EXPLAIN=1; shift ;;
        --drop_strong) DROP="--drop_strong"; shift ;;
        --rebuild) REBUILD=1; shift ;;
        --max-normal) MAX_NORMAL="$2"; shift 2 ;;
        --cpu) DEVICE="cpu"; shift ;;
        --device) DEVICE="$2"; shift 2 ;;
        --train-dir) TRAIN_DIR="$2"; shift 2 ;;
        --val-dir) VAL_DIR="$2"; shift 2 ;;
        --test-dir) TEST_DIR="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) echo "unknown arg: $1" >&2; usage 2 ;;
    esac
done

# ---- resolve the three sessions (newest of each role unless overridden) ----------
latest() { ls -d "$HERE"/session_"$1"_*/ 2>/dev/null | sort | tail -1; }
[[ -n "$TRAIN_DIR" ]] || TRAIN_DIR="$(latest train)"
[[ -n "$VAL_DIR"   ]] || VAL_DIR="$(latest val)"
[[ -n "$TEST_DIR"  ]] || TEST_DIR="$(latest test)"
for pair in "train:$TRAIN_DIR" "val:$VAL_DIR" "test:$TEST_DIR"; do
    role="${pair%%:*}"; dir="${pair#*:}"
    [[ -n "$dir" && -d "$dir" ]] || { echo "ERROR: no $role session found. Capture one: ./05_run_attacks.sh --split $role" >&2; exit 1; }
done
TRAIN_DIR="${TRAIN_DIR%/}"; VAL_DIR="${VAL_DIR%/}"; TEST_DIR="${TEST_DIR%/}"
echo "train: $TRAIN_DIR"
echo "val  : $VAL_DIR"
echo "test : $TEST_DIR"

# ---- preconditions (fail fast) --------------------------------------------------
[[ -x "$PY" ]] || { echo "ERROR: venv python not found at $PY" >&2
    echo "       create it:  python3 -m venv $HERE/.venv && $HERE/.venv/bin/pip install -r $HERE/requirements-model.txt" >&2; exit 1; }
docker image inspect flowtools:local >/dev/null 2>&1 || { echo "ERROR: flowtools:local image missing (needed for the L3/4 netflows)." >&2
    echo "       build it:  docker build -f $HERE/Dockerfile.flowtools -t flowtools:local $HERE" >&2; exit 1; }
"$PY" -c 'import torch, torch_geometric' 2>/dev/null || { echo "ERROR: torch + torch_geometric not in the venv." >&2
    echo "       install:  $HERE/.venv/bin/pip install -r $HERE/requirements-model.txt" >&2; exit 1; }
for dir in "$TRAIN_DIR" "$VAL_DIR" "$TEST_DIR"; do
    for need in logs pcaps labels.csv; do
        [[ -e "$dir/$need" ]] || { echo "ERROR: $dir is missing $need (not a complete capture session)." >&2; exit 1; }
    done
    compgen -G "$dir/pods_*.json" >/dev/null || { echo "ERROR: $dir has no pods_*.json snapshot." >&2; exit 1; }
done

# ---- build both views for one session (skip if already built) -------------------
build_one() {
    local dir="$1"
    if [[ $REBUILD == 0 && -s "$dir/dataset/netflows.csv" && -s "$dir/dataset/observed_services.graphml" ]]; then
        echo "  dataset present -> skip (use --rebuild to force)"
        return 0
    fi
    echo "  [L7]  build_dataset.py"
    "$PY" "$HERE/build_dataset.py" --logs "$dir/logs" --pods "$dir/pods_*.json" \
        --labels "$dir/labels.csv" --out_dir "$dir/dataset" || { echo "build_dataset failed for $dir" >&2; exit 1; }
    echo "  [L3/4] 04_pcap_to_flows.sh"
    "$HERE/04_pcap_to_flows.sh" "$dir/pcaps" "$dir/labels.csv" "$dir/dataset/netflows.csv" \
        || { echo "04_pcap_to_flows failed for $dir" >&2; exit 1; }
    # show the per-class netflow makeup so thin classes are visible
    "$PY" - "$dir/dataset/netflows.csv" <<'PY' || true
import csv, sys
from collections import Counter
c = Counter()
with open(sys.argv[1]) as f:
    for row in csv.DictReader(f):
        c[(row.get('label') or 'normal').strip()] += 1
print('  netflow label counts:', dict(c))
PY
}

echo; echo "==> build datasets"
for dir in "$TRAIN_DIR" "$VAL_DIR" "$TEST_DIR"; do
    echo "- ${dir##*/}"
    build_one "$dir"
done

# ---- compare the views ----------------------------------------------------------
TR="$TRAIN_DIR/dataset"; VA="$VAL_DIR/dataset"; TE="$TEST_DIR/dataset"
COMMON=(--netflows "$TR/netflows.csv" --graphml "$TR/observed_services.graphml"
        --val_netflows "$VA/netflows.csv" --test_netflows "$TE/netflows.csv"
        --seeds "$SEEDS" --max_normal "$MAX_NORMAL" --device "$DEVICE")
[[ -n "$DROP" ]] && COMMON+=("$DROP")

echo; echo "==> compare (seeds $SEEDS | max_normal $MAX_NORMAL | device $DEVICE${DROP:+ | $DROP})"
if [[ $SWEEP == 1 ]]; then
    "$PY" "$HERE/two_view_hetero_gat.py" "${COMMON[@]}" --sweep
    [[ $EXPLAIN == 1 ]] && echo "note: --explain is ignored with --sweep; run without --sweep for the figures."
else
    for V in l34 l7 both; do
        echo; echo "===== views=$V ====="
        "$PY" "$HERE/two_view_hetero_gat.py" "${COMMON[@]}" --views "$V"
    done
    if [[ $EXPLAIN == 1 ]]; then
        echo; echo "===== per-alert view attention (both) -> $TE/explain ====="
        "$PY" "$HERE/two_view_hetero_gat.py" "${COMMON[@]}" --views both --explain "$TEST_DIR/explain"
    fi
fi
echo; echo "==> done."
