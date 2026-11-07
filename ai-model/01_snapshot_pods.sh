#!/usr/bin/env bash
# Save a pod-IP -> service-name map. Run this once at the START of a collection
# session (pod IPs change on every restart/reschedule, so re-run after any
# `kubectl rollout restart` too).
#
# Captures ALL namespaces by default so the istio-system ingress gateway is in the
# map too (otherwise gateway traffic resolves to external:<ip>). Pass a space-
# separated list to narrow it:  ./01_snapshot_pods.sh "default istio-system"
set -euo pipefail
NS="${1:-}"
OUT="pods_$(date +%Y%m%dT%H%M%S).json"

if [[ -z "$NS" ]]; then
    kubectl get pods -A -o json > "$OUT"
else
    # one `kubectl get` per namespace, merged into a single items[] list
    tmpdir="$(mktemp -d)"; trap 'rm -rf "$tmpdir"' EXIT
    for n in $NS; do kubectl get pods -n "$n" -o json > "$tmpdir/$n.json"; done
    python3 - "$OUT" "$tmpdir"/*.json <<'PY'
import json, sys
out, parts = sys.argv[1], sys.argv[2:]
items = []
for p in parts:
    items += json.load(open(p)).get('items', [])
json.dump({"items": items}, open(out, "w"))
PY
fi

echo "wrote $OUT"
python3 - "$OUT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for it in d['items']:
    ip = it['status'].get('podIP', '?')
    app = it['metadata'].get('labels', {}).get('app', '?')
    print(f"{ip:<16} {app:<24} {it['metadata']['name']}")
PY
