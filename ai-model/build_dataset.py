"""
Turn captured Istio access logs into a labeled L7 dataset: one row per request,
an aggregated pseudo-flow table, and a GraphML of the *observed* service-call graph
(replaces the synthetic microservice-dependency mapping used in two_view_hetero_gat.py
with a real one from your own cluster).

This is the L7 side. For a real, INDEPENDENT L3/4 view (packet capture -> Argus),
use 03_capture_pcap.sh + 04_pcap_to_flows.sh -> netflows.csv. The flows.csv written
here is a convenience L3/4-*shaped* aggregate of the SAME L7 lines and is correlated
with requests.csv by construction -- prefer netflows.csv for the L3/4 view.

Inputs
  --logs DIR        folder of *.log files from 02_stream_logs.sh (one per pod,
                     each line a JSON object per the istio-logging.yaml format)
  --pods FILE[,...]  one or more pods_*.json snapshots from 01_snapshot_pods.sh
  --labels FILE      labels.csv: start_time,end_time,label,source_ip,match_ua,notes
                     (source_ip blank = any; match_ua = substring of user_agent that
                     identifies attacker requests -- the most reliable label key)

Outputs (written to --out_dir)
  requests.csv           one row per observed request/connection, labeled
  flows.csv               caller_ip/callee_pod pairs aggregated into time buckets
  observed_services.graphml   nodes = services seen, edges = observed calls

Usage
  python build_dataset.py --logs logs --pods pods_*.json --labels labels.csv --out_dir dataset
  python build_dataset.py --selftest     # parser unit test on synthetic data, no cluster needed
"""
import argparse
import csv
import glob
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone

import networkx as nx
import pandas as pd

# upstream_cluster looks like "inbound|8080||;" or "outbound|80||frontend.default...;"
# or "PassthroughCluster" / "BlackHoleCluster" / null. We only need the direction word.
DIRECTION_RE = re.compile(r'^(inbound|outbound)\|')


def parse_ts(s):
    """Envoy %START_TIME% / labels.csv timestamps: RFC3339, 'Z' or offset, optional fractional seconds."""
    s = s.strip()
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    return datetime.fromisoformat(s).astimezone(timezone.utc)


def strip_port(addr):
    """'10.244.0.5:54321' -> ('10.244.0.5', '54321'); bare IPs / '-' -> (addr, '')."""
    if not addr or addr == '-':
        return addr, ''
    if addr.count(':') == 1:                     # skip IPv6 (rare on minikube pod IPs)
        ip, port = addr.rsplit(':', 1)
        return ip, port
    return addr, ''


def classify(upstream_cluster):
    """Return the Envoy cluster direction: inbound / outbound / passthrough / blackhole / none."""
    uc = upstream_cluster or ''
    m = DIRECTION_RE.match(uc)
    if m:
        return m.group(1)
    if uc.startswith('PassthroughCluster'):
        return 'passthrough'
    if uc.startswith('BlackHoleCluster'):
        return 'blackhole'
    return 'none'


def load_pod_maps(pod_globs):
    """List of (snapshot_time, {ip: service}, {pod_name: service}) sorted oldest-first.
    `sa` in the log line is the primary source of a pod's own service identity; the
    pod-name map here is only a fallback for when `sa` is missing or 'default'."""
    files = sorted({f for g in pod_globs for f in glob.glob(g)})
    assert files, f'no pod snapshot files matched {pod_globs}'
    maps = []
    for f in files:
        t = datetime.fromtimestamp(os.path.getmtime(f), tz=timezone.utc)
        d = json.load(open(f))
        ip2svc, name2svc = {}, {}
        for it in d['items']:
            ip = it.get('status', {}).get('podIP')
            name = it.get('metadata', {}).get('name')
            app = it.get('metadata', {}).get('labels', {}).get('app')
            if ip and app:
                ip2svc[ip] = app
            if name and app:
                name2svc[name] = app
        maps.append((t, ip2svc, name2svc))
    maps.sort(key=lambda x: x[0])
    return maps


def resolve_ip(ip, ts, maps):
    if not ip or ip == '-':
        return 'unknown'
    chosen = maps[0][1]
    for t, ip2svc, _ in maps:
        if t <= ts:
            chosen = ip2svc
        else:
            break
    return chosen.get(ip, f'external:{ip}')


def resolve_pod_name(pod_name, ts, maps):
    if not pod_name:
        return None
    chosen = maps[0][2]
    for t, _, name2svc in maps:
        if t <= ts:
            chosen = name2svc
        else:
            break
    return chosen.get(pod_name)


def load_labels(path):
    rows = []
    with open(path) as f:
        for r in csv.DictReader(f):
            if not r['start_time'].strip():
                continue
            rows.append(dict(
                start=parse_ts(r['start_time']), end=parse_ts(r['end_time']),
                label=r['label'].strip(),
                source_ip=(r.get('source_ip') or '').strip() or None,
                match_ua=(r.get('match_ua') or '').strip() or None))
    return rows


def label_row(ts, caller_ip, user_agent, is_entry, labels):
    """Entry-point labeling. Priority:
      1) match_ua window whose substring is in the request's user_agent (attacker tag);
      2) a time (+optional source_ip) window: attack label on ENTRY rows, '<label>_fanout'
         on internal fan-out so it can be excluded or treated as its own class;
      3) otherwise 'normal'.
    """
    ua = user_agent if isinstance(user_agent, str) else ''
    for w in labels:                                 # 1) UA-tagged attacker requests
        if w['match_ua'] and w['start'] <= ts <= w['end'] and w['match_ua'] in ua:
            return w['label']
    for w in labels:                                 # 2) time/source_ip window
        if w['match_ua']:
            continue
        if w['start'] <= ts <= w['end'] and (w['source_ip'] is None or w['source_ip'] == caller_ip):
            return w['label'] if is_entry else w['label'] + '_fanout'
    return 'normal'                                  # 3) baseline


def _is_gateway(j):
    return (j.get('ns') == 'istio-system'
            or str(j.get('pod', '')).startswith('istio-ingressgateway'))


def parse_logs(log_files, pod_maps, labels):
    """Keep ALL line types (not just inbound), tagged with direction + record_type, and
    drop only the internal client-side OUTBOUND duplicates of a request that also has an
    inbound server-side record. Gateway, malformed and passthrough lines are kept -- they
    carry the most attack signal."""
    rows = []
    bad = 0
    for path in log_files:
        with open(path, errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    j = json.loads(line)
                except json.JSONDecodeError:
                    bad += 1
                    continue
                if not isinstance(j, dict) or 'upstream_cluster' not in j:
                    bad += 1               # non-access-log stdout (startup banners, etc.)
                    continue
                try:
                    ts = parse_ts(j['ts'])
                except Exception:
                    bad += 1
                    continue

                direction = classify(j.get('upstream_cluster', ''))
                gateway = _is_gateway(j)
                method = j.get('method')
                # record_type: malformed (no upstream + codec error) / tcp (L4) / http (L7)
                if not j.get('upstream_cluster') and j.get('response_flags') not in ('-', None):
                    record_type = 'malformed'
                elif method in (None, '-') and j.get('protocol') in (None, '-'):
                    record_type = 'tcp'
                else:
                    record_type = 'http'

                # De-dup: keep the server-side inbound record; keep gateway/malformed/
                # passthrough/blackhole (no inbound twin); drop internal client-side
                # outbound duplicates.
                keep = (direction == 'inbound' or gateway
                        or record_type == 'malformed'
                        or direction in ('passthrough', 'blackhole'))
                if not keep:
                    continue

                caller_ip, caller_port = strip_port(j.get('downstream_remote_addr', ''))
                callee_ip, callee_port = strip_port(j.get('downstream_local_addr', ''))
                caller_svc = resolve_ip(caller_ip, ts, pod_maps)
                # callee identity: `sa` first (self-reported, no snapshot join), but NOT
                # when it is 'default' (redis-cart / hello-minikube use the default SA);
                # then fall back to the pod-name snapshot lookup.
                sa = j.get('sa')
                if sa and sa not in ('-', 'default'):
                    callee_svc = sa
                else:
                    callee_svc = (resolve_pod_name(j.get('pod'), ts, pod_maps)
                                  or (sa if sa and sa != '-' else None) or 'unknown')

                external_caller = caller_svc.startswith('external:') or caller_svc == 'unknown'
                is_entry = (gateway or record_type == 'malformed'
                            or direction in ('passthrough', 'blackhole')
                            or (direction == 'inbound' and external_caller))

                rows.append(dict(
                    ts=ts, direction=direction, record_type=record_type, is_entry=is_entry,
                    caller_service=caller_svc, caller_ip=caller_ip, caller_port=caller_port,
                    callee_service=callee_svc, callee_pod=j.get('pod'),
                    callee_ip=callee_ip, callee_port=callee_port,
                    method=method, path=j.get('path'), protocol=j.get('protocol'),
                    authority=j.get('authority'),
                    response_code=j.get('response_code'), grpc_status=j.get('grpc_status'),
                    response_flags=j.get('response_flags'),
                    response_code_details=j.get('response_code_details'),
                    duration_ms=_num(j.get('duration_ms')), bytes_rx=_num(j.get('bytes_rx')),
                    bytes_tx=_num(j.get('bytes_tx')), route_name=j.get('route_name'),
                    user_agent=j.get('user_agent'), xff=j.get('xff'),
                    request_id=j.get('request_id')))
    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values('ts').reset_index(drop=True)
        df['is_err'] = [_is_err(rc, gs) for rc, gs in zip(df['response_code'], df['grpc_status'])]
        df['label'] = [label_row(ts, ip, ua, ent, labels)
                       for ts, ip, ua, ent in zip(df['ts'], df['caller_ip'],
                                                   df['user_agent'], df['is_entry'])]
    if bad:
        print(f'skipped {bad} unparseable/non-access-log lines')
    return df


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def _is_err(response_code, grpc_status):
    """A request failed if HTTP >= 400 OR gRPC carried a non-OK status. gRPC errors ride
    on HTTP 200, so response_code alone misses them."""
    try:
        if float(response_code) >= 400:
            return True
    except (TypeError, ValueError):
        pass
    gs = str(grpc_status)
    return gs not in ('0', 'OK', '-', '', 'None', 'nan', 'null')


def _flow_label(labels):
    """Majority label for a bucket, but ANY attack request makes the bucket an attack
    (prefer the most common non-normal label over 'normal')."""
    non_norm = [x for x in labels if x != 'normal']
    if non_norm:
        return Counter(non_norm).most_common(1)[0][0]
    return 'normal'


def build_flows(df, bucket_s=5):
    """Aggregate requests into (caller_ip, callee_pod, time-bucket) pseudo-flows.
    Derived from the SAME L7 logs as requests.csv -- a convenience L3/4-shaped view, not
    an independent capture. For the real L3/4 view use netflows.csv (04_pcap_to_flows.sh)."""
    if df.empty:
        return df
    g = df.copy()
    # pandas 2 stores datetime64 as ns, pandas 3 as us -> normalise to seconds first,
    # otherwise astype('int64') yields different units and the buckets explode.
    g['bucket'] = (g['ts'].dt.as_unit('s').astype('int64') // bucket_s) * bucket_s
    agg = g.groupby(['caller_ip', 'callee_pod', 'bucket']).agg(
        n_requests=('ts', 'count'), bytes_rx=('bytes_rx', 'sum'), bytes_tx=('bytes_tx', 'sum'),
        mean_duration_ms=('duration_ms', 'mean'), max_duration_ms=('duration_ms', 'max'),
        n_err=('is_err', 'sum'),
        label=('label', _flow_label),
        caller_service=('caller_service', 'first'), callee_service=('callee_service', 'first'),
    ).reset_index()
    return agg


def build_service_graph(df):
    g = nx.DiGraph()
    if df.empty:
        return g
    for (c, s), n in df.groupby(['caller_service', 'callee_service']).size().items():
        g.add_edge(c, s, weight=int(n))
    return g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--logs', default='logs')
    ap.add_argument('--pods', nargs='+', default=['pods_*.json'])
    ap.add_argument('--labels', default='labels.csv')
    ap.add_argument('--out_dir', default='dataset')
    ap.add_argument('--bucket_s', type=int, default=5)
    a = ap.parse_args()

    if a.selftest:
        return _selftest()

    pod_maps = load_pod_maps(a.pods)
    labels = load_labels(a.labels)
    log_files = sorted(glob.glob(os.path.join(a.logs, '*.log')))
    assert log_files, f'no *.log files in {a.logs}'
    df = parse_logs(log_files, pod_maps, labels)
    print(f'{len(df):,} records parsed')
    if df.empty:
        print('nothing to write')
        return
    print(df['label'].value_counts())
    print('record types:', dict(df['record_type'].value_counts()))

    os.makedirs(a.out_dir, exist_ok=True)
    df.to_csv(os.path.join(a.out_dir, 'requests.csv'), index=False)
    flows = build_flows(df, a.bucket_s)
    flows.to_csv(os.path.join(a.out_dir, 'flows.csv'), index=False)
    g = build_service_graph(df)
    nx.write_graphml(g, os.path.join(a.out_dir, 'observed_services.graphml'))
    print(f'wrote {a.out_dir}/requests.csv ({len(df)} rows), '
          f'{a.out_dir}/flows.csv ({len(flows)} rows), '
          f'{a.out_dir}/observed_services.graphml ({g.number_of_nodes()} services, {g.number_of_edges()} edges)')


def _selftest():
    """Runs the parser against synthetic log lines + a synthetic pod snapshot, no cluster needed."""
    import tempfile
    tmp = tempfile.mkdtemp()
    pods = {"items": [
        {"status": {"podIP": "10.244.1.47"}, "metadata": {"labels": {"app": "frontend"}, "name": "frontend-abc"}},
        {"status": {"podIP": "10.244.1.43"}, "metadata": {"labels": {"app": "cartservice"}, "name": "cartservice-abc"}},
        {"status": {"podIP": "10.244.1.46"}, "metadata": {"labels": {"app": "redis-cart"}, "name": "redis-cart-abc"}},
    ]}
    pods_path = os.path.join(tmp, 'pods_1.json')
    json.dump(pods, open(pods_path, 'w'))

    L = [
        # 1) gateway entry, attacker UA -> kept, is_entry, labeled by match_ua
        dict(ts="2026-01-01T00:10:05.100Z", pod="istio-ingressgateway-x", ns="istio-system", sa="-",
             method="GET", path="/", protocol="HTTP/1.1", response_code="200", grpc_status="-",
             response_flags="-", duration_ms="5", bytes_rx="0", bytes_tx="500", user_agent="atk-scanner/1.0",
             xff="10.244.0.1", downstream_remote_addr="10.244.0.1:5000",
             downstream_local_addr="10.244.1.21:8080", upstream_cluster="outbound|80||frontend.default.svc.cluster.local;"),
        # 2) frontend inbound from external, same attacker UA -> kept, entry, UA-labeled
        dict(ts="2026-01-01T00:10:05.101Z", pod="frontend-abc", ns="default", sa="frontend",
             method="GET", path="/", protocol="HTTP/1.1", response_code="200", grpc_status="-",
             response_flags="-", duration_ms="4", bytes_rx="0", bytes_tx="500", user_agent="atk-scanner/1.0",
             downstream_remote_addr="10.244.0.1:0", downstream_local_addr="10.244.1.47:8080",
             upstream_cluster="inbound|8080||;"),
        # 3) internal fan-out during the window, NOT the attacker UA -> kept, '_fanout'
        dict(ts="2026-01-01T00:10:05.200Z", pod="cartservice-abc", ns="default", sa="cartservice",
             method="POST", path="/hipstershop.CartService/GetCart", protocol="HTTP/2",
             response_code="200", grpc_status="0", response_flags="-", duration_ms="3",
             bytes_rx="120", bytes_tx="340", user_agent="grpc-go/1.71.0",
             downstream_remote_addr="10.244.1.47:4444", downstream_local_addr="10.244.1.43:7070",
             upstream_cluster="inbound|7070||;"),
        # 4) the client-side OUTBOUND duplicate of (3) -> dropped
        dict(ts="2026-01-01T00:10:05.200Z", pod="frontend-abc", ns="default", sa="frontend",
             method="POST", path="/hipstershop.CartService/GetCart", protocol="HTTP/2",
             response_code="200", grpc_status="0", response_flags="-", duration_ms="3",
             bytes_rx="120", bytes_tx="340", user_agent="grpc-go/1.71.0",
             downstream_remote_addr="10.244.1.47:4444", downstream_local_addr="10.244.1.43:7070",
             upstream_cluster="outbound|7070||cartservice.default.svc.cluster.local;"),
        # 5) malformed HTTP -> kept, entry
        dict(ts="2026-01-01T00:10:06.000Z", pod="frontend-abc", ns="default", sa="frontend",
             method=None, path=None, protocol="HTTP/1.1", response_code="400", grpc_status=None,
             response_flags="DPE", response_code_details="http1.codec_error", duration_ms="0",
             bytes_rx="0", bytes_tx="11", user_agent=None,
             downstream_remote_addr="10.244.0.1:6000", downstream_local_addr="10.244.1.47:8080",
             upstream_cluster=None),
        # 6) passthrough scan line -> kept, entry
        dict(ts="2026-01-01T00:10:06.500Z", pod="frontend-abc", ns="default", sa="frontend",
             method=None, path=None, protocol=None, response_code="0", grpc_status=None,
             response_flags="-", duration_ms="1", bytes_rx="0", bytes_tx="0", user_agent=None,
             downstream_remote_addr="10.244.1.99:41500", downstream_local_addr="10.244.1.47:12345",
             upstream_cluster="PassthroughCluster;"),
        # 7) redis TCP inbound, sa='default' -> callee via pod-name fallback, record_type tcp, normal
        dict(ts="2026-01-01T00:20:00.000Z", pod="redis-cart-abc", ns="default", sa="default",
             method=None, path=None, protocol=None, response_code="0", grpc_status=None,
             response_flags="-", duration_ms="12", bytes_rx="554", bytes_tx="536", user_agent=None,
             downstream_remote_addr="10.244.1.43:53230", downstream_local_addr="10.244.1.46:6379",
             upstream_cluster="inbound|6379||;"),
        # 8) gRPC error on HTTP 200 -> is_err True, normal (outside any window)
        dict(ts="2026-01-01T00:20:01.000Z", pod="cartservice-abc", ns="default", sa="cartservice",
             method="POST", path="/hipstershop.CartService/GetCart", protocol="HTTP/2",
             response_code="200", grpc_status="Unavailable", response_flags="UH", duration_ms="2",
             bytes_rx="10", bytes_tx="0", user_agent="grpc-go/1.71.0",
             downstream_remote_addr="10.244.1.47:5555", downstream_local_addr="10.244.1.43:7070",
             upstream_cluster="inbound|7070||;"),
        "not json {{{",                                  # 9) malformed JSON -> skipped
    ]
    log_path = os.path.join(tmp, 'mixed.log')
    with open(log_path, 'w') as f:
        for l in L:
            f.write((json.dumps(l) if isinstance(l, dict) else l) + '\n')

    labels_path = os.path.join(tmp, 'labels.csv')
    with open(labels_path, 'w') as f:
        f.write('start_time,end_time,label,source_ip,match_ua,notes\n')
        # UA-tagged attack window (covers lines 1-6); the fan-out line 3 is NOT the UA.
        f.write('2026-01-01T00:10:00Z,2026-01-01T00:10:30Z,http_flood,,atk-scanner,ua-tagged attack\n')
        # a plain time window too, to exercise entry vs _fanout
        f.write('2026-01-01T00:10:00Z,2026-01-01T00:10:30Z,timewin,,,time-only window\n')

    pod_maps = load_pod_maps([pods_path])
    labels = load_labels(labels_path)
    df = parse_logs([log_path], pod_maps, labels)

    got = dict(df['record_type'].value_counts())
    # 8 kept (line 4 outbound dup dropped, line 9 bad json dropped)
    assert len(df) == 7, f'expected 7 kept rows, got {len(df)}\n{df[["ts","direction","record_type"]]}'
    assert got.get('http') == 4 and got.get('tcp') == 2 and got.get('malformed') == 1, got
    # dedup: the only surviving 'outbound' row is the gateway entry (its internal
    # client-side twin, line 4, was dropped); gateway lines are outbound but have no
    # inbound twin, so they are kept.
    outb = df[df['direction'] == 'outbound']
    assert len(outb) == 1 and outb.iloc[0]['caller_ip'] == '10.244.0.1', outb[['caller_ip', 'callee_pod']].to_dict('records')
    # UA labeling: the 2 attacker-UA rows (gateway + frontend inbound) are http_flood
    assert (df['label'] == 'http_flood').sum() == 2, df[['user_agent', 'label']].to_dict('records')
    # fan-out: the grpc internal call in the window, without the UA, is a *_fanout class
    assert 'timewin_fanout' in set(df['label']), sorted(set(df['label']))
    # callee via sa, with 'default' falling back to the pod-name app label
    cart = df[df['callee_pod'] == 'cartservice-abc']
    assert set(cart['callee_service']) == {'cartservice'}, cart['callee_service'].tolist()
    redis = df[df['callee_pod'] == 'redis-cart-abc'].iloc[0]
    assert redis['callee_service'] == 'redis-cart' and redis['record_type'] == 'tcp', dict(redis)
    # gRPC-on-200 error is counted
    assert bool(df[df['response_flags'] == 'UH'].iloc[0]['is_err']) is True
    # entry flags
    gw = df[df['caller_ip'] == '10.244.0.1']
    assert gw['is_entry'].all(), gw[['caller_ip', 'is_entry']].to_dict('records')

    flows = build_flows(df, bucket_s=5)
    # bucket fix: buckets are ~5 s apart, not thousands of seconds
    span = flows['bucket'].max() - flows['bucket'].min()
    assert span < 10000, f'buckets exploded (pandas-unit bug): span={span}'
    assert (flows['n_err'] >= 1).any(), 'gRPC error not aggregated into any flow'

    g = build_service_graph(df)
    assert ('external:10.244.0.1', 'frontend') in g.edges(), list(g.edges())

    print('selftest OK')
    print(df[['ts', 'direction', 'record_type', 'is_entry', 'caller_service',
              'callee_service', 'label']].to_string())
    print('\nflows:\n', flows[['caller_ip', 'callee_service', 'bucket', 'n_requests', 'n_err', 'label']].to_string())


if __name__ == '__main__':
    main()
