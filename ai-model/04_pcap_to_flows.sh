#!/usr/bin/env bash
# Turn captured pcaps into an INDEPENDENT L3/4 flow table (netflows.csv), using Argus
# -- the same extractor UNSW-NB15 was built with -- so the features line up with the
# UNSW schema the model already knows. Optionally also runs Zeek for conn/http logs.
#
# This is the real L3/4 view. It replaces the derived flows.csv (which is aggregated
# from the SAME Istio logs as the L7 view and so is correlated by construction).
#
# Prereqs:
#   - pcaps fetched by 03_capture_pcap.sh (default dir: ai-model/pcaps/cap)
#   - flowtools image built:  docker build -f Dockerfile.flowtools -t flowtools:local .
#   - labels.csv (same file the L7 build uses): start_time,end_time,label,source_ip,notes
#
# Usage:
#   ./04_pcap_to_flows.sh [PCAP_DIR] [LABELS] [OUT]
#   ./04_pcap_to_flows.sh pcaps/cap labels.csv dataset/netflows.csv
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PCAP_DIR="${1:-$HERE/pcaps/cap}"
LABELS="${2:-$HERE/labels.csv}"
OUT="${3:-$HERE/dataset/netflows.csv}"
IMG="${FLOWTOOLS_IMG:-flowtools:local}"

[[ -d "$PCAP_DIR" ]] || { echo "no pcap dir: $PCAP_DIR (run ./03_capture_pcap.sh fetch)" >&2; exit 1; }
mapfile -t PCAPS < <(find "$PCAP_DIR" -name '*.pcap' | sort)
[[ ${#PCAPS[@]} -gt 0 ]] || { echo "no *.pcap under $PCAP_DIR" >&2; exit 1; }
mkdir -p "$(dirname "$OUT")"

# Argus ra field set, named to match the UNSW-NB15 columns the model consumes.
# stime/dur/proto/state/addrs/ports + per-direction packet, byte, ttl, window, load,
# loss and mean-size counters. '-c ,' = CSV, '-n' = no name lookup, '-u' = epoch time.
RA_FIELDS='stime,dur,proto,saddr,sport,daddr,dport,state,spkts,dpkts,sbytes,dbytes,sttl,dttl,swin,dwin,sload,dload,sloss,dloss,smeansz,dmeansz,sjit,djit,tcprtt,synack,ackdat'
HDR="$RA_FIELDS"

echo "extracting ${#PCAPS[@]} pcap(s) with Argus -> flow records"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo "$HDR" > "$TMP/flows_raw.csv"

for p in "${PCAPS[@]}"; do
    d="$(cd "$(dirname "$p")" && pwd)"; b="$(basename "$p")"
    # argus: pcap -> .argus ; racluster: merge bi-directional ; ra: -> CSV rows.
    # -L-1 suppresses Argus's own column-header line (otherwise it leaks in as a row).
    docker run --rm -v "$d":/in:ro "$IMG" \
        "argus -r /in/'$b' -w /tmp/o.argus >/dev/null 2>&1 && \
         racluster -r /tmp/o.argus -w /tmp/c.argus >/dev/null 2>&1 && \
         ra -r /tmp/c.argus -n -u -L-1 -c , -s $RA_FIELDS 2>/dev/null" \
        | grep -viE '^stime|^starttime|^$' >> "$TMP/flows_raw.csv" || true
done

n=$(($(wc -l < "$TMP/flows_raw.csv") - 1))
echo "got $n flow records; labeling from $LABELS"

# Label each flow by time window + optional source_ip (pcap keeps REAL source IPs, so
# source_ip labeling is reliable here for in-cluster attackers). Default label: normal.
python3 -I - "$TMP/flows_raw.csv" "$LABELS" "$OUT" <<'PY'
import csv, sys
from datetime import datetime, timezone

flows_path, labels_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

def parse_ts(s):
    s = s.strip()
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    return datetime.fromisoformat(s).astimezone(timezone.utc)

windows = []
with open(labels_path) as f:
    for r in csv.DictReader(f):
        if not r['start_time'].strip():
            continue
        windows.append(dict(start=parse_ts(r['start_time']), end=parse_ts(r['end_time']),
                            label=r['label'].strip(),
                            src=(r.get('source_ip') or '').strip() or None))

def label_of(epoch, saddr, daddr):
    ts = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
    for w in windows:
        if w['start'] <= ts <= w['end'] and (w['src'] is None or w['src'] in (saddr, daddr)):
            return w['label']
    return 'normal'

with open(flows_path) as fin, open(out_path, 'w', newline='') as fout:
    r = csv.DictReader(fin)
    w = csv.writer(fout)
    w.writerow(r.fieldnames + ['label'])
    # Keep only real IP flows; drop Argus management records (proto 'man', saddr '0')
    # and non-IP chatter (arp/rarp) that aren't part of the L3/4 traffic model.
    KEEP = {'tcp', 'udp', 'icmp', 'igmp', 'ipv6-icmp', 'ipnip', 'ip'}
    counts, dropped = {}, 0
    for row in r:
        proto = (row.get('proto') or '').strip().lower()
        saddr = (row.get('saddr') or '').strip()
        if proto not in KEEP or saddr in ('', '0'):
            dropped += 1
            continue
        try:
            lab = label_of(row['stime'], saddr, (row.get('daddr') or '').strip())
        except Exception:
            lab = 'normal'
        counts[lab] = counts.get(lab, 0) + 1
        w.writerow([row[k] for k in r.fieldnames] + [lab])
print('label counts:', counts, '| dropped non-IP/mgmt rows:', dropped)
PY

echo "wrote $OUT"

# Optional: Zeek conn/http logs for the Bro-derived fields (trans_depth, service, etc.)
if [[ "${ZEEK:-0}" == "1" ]]; then
    echo "running Zeek (conn.log, http.log) ..."
    ZD="$(dirname "$OUT")/zeek"; mkdir -p "$ZD"
    for p in "${PCAPS[@]}"; do
        d="$(cd "$(dirname "$p")" && pwd)"; b="$(basename "$p")"
        docker run --rm -v "$d":/in:ro -v "$ZD":/out zeek/zeek:7.0.6 \
            bash -lc "cd /out && zeek -r /in/'$b' LogAscii::use_json=T >/dev/null 2>&1 || true"
    done
    echo "zeek logs in $ZD"
fi
