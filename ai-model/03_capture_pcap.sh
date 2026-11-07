#!/usr/bin/env bash
# Control the L3/4 packet capture that runs alongside Istio (see
# capture-daemonset.yaml and docs/build_dataset/l3-capture.md).
#
# Usage:
#   ./03_capture_pcap.sh start          # deploy the capture pod, print a UTC start mark
#   ./03_capture_pcap.sh mark "<note>"  # print a UTC timestamp for labels.csv
#   ./03_capture_pcap.sh fetch [DIR]    # copy pcaps off the node into DIR (default: pcaps)
#   ./03_capture_pcap.sh stop           # delete the capture pod (pcaps stay on the node
#                                       # until the pod's hostPath is cleared)
#
# Typical session:
#   ./03_capture_pcap.sh start          # BEFORE any traffic/attacks
#   ./02_stream_logs.sh &               # Istio L7 logs, same window
#   ... run baseline + attacks, recording windows with `mark` into labels.csv ...
#   ./03_capture_pcap.sh fetch pcaps
#   ./03_capture_pcap.sh stop
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=kube-system
SEL=app=pcap-capture

mark() { date -u +"%Y-%m-%dT%H:%M:%S.%3NZ  ${*:-}"; }

start() {
    kubectl apply -f "$HERE/capture-daemonset.yaml"
    echo "waiting for capture pod..."
    kubectl -n "$NS" rollout status ds/pcap-capture --timeout=120s
    echo "capture started. START MARK:"
    mark "capture start"
}

stop() {
    kubectl -n "$NS" delete -f "$HERE/capture-daemonset.yaml" --ignore-not-found
    echo "capture stopped. (pcaps remain under /var/log/pcap-capture on the node)"
}

fetch() {
    local out="${1:-pcaps}"
    mkdir -p "$out"
    local pod
    pod=$(kubectl -n "$NS" get pod -l "$SEL" -o jsonpath='{.items[0].metadata.name}')
    [[ -n "$pod" ]] || { echo "no capture pod running; did you ./03_capture_pcap.sh start ?" >&2; exit 1; }
    # Flush tcpdump's buffer so the current file is complete, then copy the dir out.
    echo "copying pcaps from $pod:/cap -> $out/ ..."
    kubectl -n "$NS" cp "$pod:/cap" "$out" -c cap-bridge
    ls -la "$out"
}

case "${1:-}" in
    start) start ;;
    stop)  stop ;;
    fetch) shift; fetch "$@" ;;
    mark)  shift; mark "$@" ;;
    *) echo "usage: $0 {start|stop|fetch [DIR]|mark \"<note>\"}" >&2; exit 2 ;;
esac
