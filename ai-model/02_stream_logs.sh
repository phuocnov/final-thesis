#!/usr/bin/env bash
# Stream every app pod's istio-proxy access log to its own file for the duration
# of a collection session. Run this in its own terminal; Ctrl-C stops all of them.
#
# Usage:
#   ./02_stream_logs.sh [namespace] [out_dir]
set -euo pipefail
NS="${1:-default}"
OUT="${2:-logs}"
mkdir -p "$OUT"

pids=()
cleanup() { echo "stopping..."; kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# Does a pod carry an istio-proxy container? On this Istio it runs as a NATIVE
# sidecar in .spec.initContainers (restartPolicy: Always), so we must look in BOTH
# containers and initContainers -- checking only .spec.containers silently matches
# nothing and you get an empty dataset.
has_proxy() {
    local p="$1"
    kubectl get pod "$p" -n "$NS" \
        -o jsonpath='{.spec.containers[*].name} {.spec.initContainers[*].name}' \
        2>/dev/null | grep -qw istio-proxy
}

stream_pod() {   # stream_pod <namespace> <pod>
    local ns="$1" p="$2"
    echo "streaming $p"
    # --since=1s: only new lines; restart the follow if the pod is replaced mid-session
    ( while kubectl get pod "$p" -n "$ns" >/dev/null 2>&1; do
          kubectl logs -f "$p" -n "$ns" -c istio-proxy --since=1s \
              >> "$OUT/$p.log" 2>>"$OUT/$p.err" || true
          sleep 1
      done ) &
    pids+=($!)
}

matched=0
for p in $(kubectl get pods -n "$NS" -o jsonpath='{.items[*].metadata.name}'); do
    if has_proxy "$p"; then stream_pod "$NS" "$p"; matched=$((matched + 1)); fi
done

# also the ingress gateway, in istio-system
igw=$(kubectl get pods -n istio-system -l app=istio-ingressgateway -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [[ -n "$igw" ]]; then
    echo "streaming $igw (ingress gateway)"
    ( while kubectl get pod "$igw" -n istio-system >/dev/null 2>&1; do
          kubectl logs -f "$igw" -n istio-system -c istio-proxy --since=1s \
              >> "$OUT/$igw.log" 2>>"$OUT/$igw.err" || true
          sleep 1
      done ) &
    pids+=($!)
    matched=$((matched + 1))
fi

if [[ "$matched" -eq 0 ]]; then
    echo "ERROR: no pods with an istio-proxy container found in namespace '$NS'." >&2
    echo "       Is the sidecar injected? kubectl get ns $NS --show-labels | grep istio-injection" >&2
    exit 1
fi

echo "logging to $OUT/ ($matched streams). Press Ctrl-C to stop."
wait
