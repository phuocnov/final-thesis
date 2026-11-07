#!/usr/bin/env bash
# Rebuild the Istio + access-logging + ingress setup that the dataset pipeline depends
# on. NONE of this is installed by `skaffold run`; it was applied by hand and a
# `minikube delete` wipes it silently (see docs/build_dataset/requirement.md §1). Run
# this after creating the cluster and BEFORE collecting data, so every pod gets a
# sidecar and Istio writes the JSON access logs.
#
# Idempotent: safe to re-run; it reconciles rather than duplicating.
#
# Usage:
#   ./00_setup_istio.sh                 # install/repair Istio + logging + gateway
#   ./00_setup_istio.sh --restart-app   # also roll the default-ns app so sidecars inject
#   ./00_setup_istio.sh --egress        # also apply the GoogleAPIs egress ServiceEntries
#   ISTIOCTL=/path/to/istioctl ./00_setup_istio.sh
#
# Order for a fresh cluster:
#   minikube start --cpus=4 --memory 4096 --disk-size 32g
#   ./00_setup_istio.sh                 # istio + logging + gateway, label the namespace
#   skaffold run                        # deploy the app (now gets sidecars)
#   # ... then 01_snapshot_pods.sh / 02_stream_logs.sh / 03_capture_pcap.sh ...
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
NS=default
RESTART_APP=0
EGRESS=0
for arg in "$@"; do
    case "$arg" in
        --restart-app) RESTART_APP=1 ;;
        --egress) EGRESS=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

# --- locate istioctl -------------------------------------------------------------
find_istioctl() {
    if [[ -n "${ISTIOCTL:-}" ]]; then echo "$ISTIOCTL"; return; fi
    if command -v istioctl >/dev/null 2>&1; then command -v istioctl; return; fi
    # newest ~/istio-*/bin/istioctl
    local c
    c=$(ls -d "$HOME"/istio-*/bin/istioctl 2>/dev/null | sort -V | tail -1 || true)
    [[ -n "$c" ]] && { echo "$c"; return; }
    return 1
}
ISTIOCTL="$(find_istioctl || true)"
if [[ -z "$ISTIOCTL" ]]; then
    echo "ERROR: istioctl not found. Install Istio and/or set ISTIOCTL=/path/to/istioctl." >&2
    echo "       (https://istio.io/latest/docs/setup/getting-started/#download)" >&2
    exit 1
fi
echo "using istioctl: $ISTIOCTL"
"$ISTIOCTL" version --remote=false 2>/dev/null | head -1 || true

# --- sanity: a cluster must be reachable -----------------------------------------
kubectl cluster-info >/dev/null 2>&1 || { echo "ERROR: no reachable cluster (minikube start?)." >&2; exit 1; }

# --- 1. install Istio with the access-log meshConfig -----------------------------
# istio-logging.yaml is an IstioOperator carrying meshConfig.accessLogFile +
# extensionProviders (the json-access-log provider). Default profile => istiod +
# istio-ingressgateway. Reconciles an existing install in place.
echo "==> installing/reconciling Istio (default profile + JSON access logging)"
"$ISTIOCTL" install -f "$ROOT/istio-logging.yaml" -y

# --- 2. label the namespace for sidecar injection --------------------------------
echo "==> labeling namespace '$NS' for sidecar injection"
kubectl label namespace "$NS" istio-injection=enabled --overwrite

# --- 3. mesh-wide access-log Telemetry -------------------------------------------
echo "==> applying Telemetry (json-logging)"
kubectl apply -f "$ROOT/telemetry.yaml"

# --- 4. ingress Gateway + VirtualServices ----------------------------------------
echo "==> applying ingress gateway + virtualservices"
kubectl apply -f "$ROOT/istio-manifests/frontend-gateway.yaml"
kubectl apply -f "$ROOT/istio-manifests/frontend.yaml"
if [[ "$EGRESS" == "1" ]]; then
    echo "==> applying GoogleAPIs egress ServiceEntries"
    kubectl apply -f "$ROOT/istio-manifests/allow-egress-googleapis.yaml"
fi

# --- 5. wait for the control plane -----------------------------------------------
echo "==> waiting for istiod + ingress gateway"
kubectl -n istio-system rollout status deploy/istiod --timeout=180s
kubectl -n istio-system rollout status deploy/istio-ingressgateway --timeout=180s

# --- 6. optionally roll the app so already-running pods pick up a sidecar ---------
if [[ "$RESTART_APP" == "1" ]]; then
    if kubectl -n "$NS" get deploy >/dev/null 2>&1 && [[ -n "$(kubectl -n "$NS" get deploy -o name)" ]]; then
        echo "==> restarting app deployments in '$NS' to inject sidecars"
        kubectl -n "$NS" rollout restart deploy
        kubectl -n "$NS" rollout status deploy --timeout=300s
    else
        echo "    (no deployments in '$NS' yet -- run 'skaffold run' to deploy the app)"
    fi
fi

# --- 7. verify -------------------------------------------------------------------
echo
echo "==> verification"
printf '  namespace label : '; kubectl get ns "$NS" -o jsonpath='{.metadata.labels.istio-injection}'; echo
printf '  telemetry       : '; kubectl -n istio-system get telemetry json-logging -o jsonpath='{.metadata.name}' 2>/dev/null || echo MISSING; echo
printf '  gateway         : '; kubectl -n "$NS" get gateway frontend-gateway -o jsonpath='{.metadata.name}' 2>/dev/null || echo MISSING; echo
printf '  accessLog config: '; kubectl -n istio-system get cm istio -o jsonpath='{.data.mesh}' | grep -q accessLogFile && echo present || echo MISSING; echo

# Confirm a proxy actually emits JSON (only if the frontend is deployed & meshed).
fe=$(kubectl -n "$NS" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [[ -n "$fe" ]]; then
    if kubectl -n "$NS" get pod "$fe" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}' | grep -qw istio-proxy; then
        echo "  frontend is meshed ($fe); recent proxy log line:"
        kubectl -n "$NS" logs "$fe" -c istio-proxy --tail=1 2>/dev/null | sed 's/^/    /' || true
        echo "  (if that is not JSON, generate a request and re-check; new config applies to new connections)"
    else
        echo "  NOTE: frontend pod has no istio-proxy -- re-run with --restart-app (or redeploy) to inject sidecars."
    fi
else
    echo "  app not deployed yet -- run 'skaffold run', then (if pods predate this) ./00_setup_istio.sh --restart-app"
fi
echo
echo "done."
