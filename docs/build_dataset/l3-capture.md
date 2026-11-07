# Capturing an independent L3/4 view alongside Istio

Companion to [`requirement.md`](./requirement.md) and [`attack-types.md`](./attack-types.md).

**Question this answers:** Istio can't see L3 (and only a weak, derived L4) — can we
run something alongside it to capture a real network-layer view? **Yes:** a packet
capture on the node, with flow features extracted by **Argus** (the same tool used to
build UNSW-NB15). This gives a genuinely *independent* L3/4 view, which also fixes the
"both views come from the same Istio logs" weakness flagged in `ai-model/README.md`.

Verified on 2026-11-08 against the running cluster; a 30 s ambient capture produced
251 clean flow records with populated UNSW-style features (see [§6](#6-what-was-verified)).

## 1. Why Istio can't do L3/4, and why a packet capture can

Istio's sidecar is an L7 proxy. It only logs connections it terminates, so it misses
SYN floods, UDP/ICMP, connection floods and kernel-handled scans, and it has no
packet-level fields (TTL, window, flags, packet counts). A packet capture sits below
the proxy and sees the actual frames, so it recovers exactly those fields.

**mTLS is not a problem.** Istio encrypts the L7 *payload* between sidecars, but the
L3/4 headers — IP addresses, ports, TCP flags, packet sizes, TTL, window — are in the
clear on the wire. Those headers are all the L3/4 view needs. (Don't try to read
application bytes from these packets; that part is encrypted. Use the Istio logs for
L7, as before.)

## 2. Where to capture

This is single-node minikube with the default bridge CNI. Every pod's veth is slaved
to one `bridge` interface (`10.244.0.1/16`), and `eth0` (`192.168.49.2`) carries
north-south traffic. So **two captures cover everything**:

| Interface | Sees |
| --- | --- |
| `bridge` | All east-west pod↔pod traffic, with **real pod IPs on both ends** |
| `eth0` | North-south: ingress gateway / NodePort traffic |

No CNI change is needed. `capture-daemonset.yaml` runs one `tcpdump` per interface in a
privileged `hostNetwork` pod (kept out of the mesh with `sidecar.istio.io/inject:
"false"`), writing rotated pcaps to a hostPath on the node.

## 3. The pipeline

Run the capture in the **same window** as the Istio L7 log streaming, so both views
cover identical traffic and share one `labels.csv`:

```
[capture, in-cluster pod]          [extract, in containers]          [dataset]
tcpdump on bridge + eth0   --->  argus -> racluster -> ra  --->  netflows.csv  --+
  (03_capture_pcap.sh)             (04_pcap_to_flows.sh)                          |--> two-view model
                                                                                  |    (captured data only)
Istio sidecars (already) --->  02_stream_logs.sh -> build_dataset.py -> requests.csv + observed_services.graphml
```

- **Argus** turns the pcap into bidirectional flow records. It is the original
  UNSW-NB15 extractor, so the fields line up with the UNSW schema the model already
  uses: `dur, sbytes, dbytes, sttl, dttl, swin, dwin, spkts, dpkts, sload, dload,
  sloss, dloss, smeansz, dmeansz, sjit, djit, tcprtt, synack, ackdat`, plus `proto`
  and `state`.
- **Zeek** (optional, `ZEEK=1`) adds `conn.log` / `http.log` for the "Bro-derived"
  fields UNSW got from Bro (e.g. `trans_depth`, service labels).
- Neither tool is installed on the host; both run in containers. Build the Argus image
  once: `docker build -f Dockerfile.flowtools -t flowtools:local ai-model`.

## 4. How to run

```sh
cd ai-model
docker build -f Dockerfile.flowtools -t flowtools:local .   # once

./03_capture_pcap.sh start            # BEFORE any traffic; prints a UTC start mark
./02_stream_logs.sh &                 # Istio L7 logs, same window (fix per requirement.md blocker 1)
./01_snapshot_pods.sh                 # pod-IP map for the L7 build

# ... run baseline loadgenerator + attacks from attack-types.md ...
./03_capture_pcap.sh mark "http_flood start"   # record windows into labels.csv
# ...
./03_capture_pcap.sh mark "http_flood end"

./03_capture_pcap.sh fetch pcaps      # copy pcaps off the node
./03_capture_pcap.sh stop             # remove the capture pod

# extract the independent L3/4 table (reuses the same labels.csv as the L7 build)
./04_pcap_to_flows.sh pcaps/cap labels.csv dataset/netflows.csv
# optional Bro-derived fields:  ZEEK=1 ./04_pcap_to_flows.sh ...
```

## 5. Labeling and the two-view join

- **Labels** reuse the `labels.csv` time windows from `requirement.md §6`. A concrete
  advantage over the L7 view: the pcap keeps **real source IPs**, so for in-cluster
  (pod-to-pod) attacks the `source_ip` column is reliable here — unlike the Istio
  logs, which collapse every external client to the gateway/NodePort NAT address.
- **Join: two tables, fused in the model.** `netflows.csv` (L3/4 flow+host view) stays
  separate from the Istio-derived `observed_services.graphml` (L7 service view). The
  model fuses them through shared host/service nodes — the same architecture the
  existing UNSW + FTGO-GraphML path uses. No fragile 5-tuple correlation through
  Istio's iptables/NAT is attempted.
- **Train on it:** a new `build_from_capture()` loader (the piece the README said was
  missing) reads `netflows.csv` into the same structure `load_flows` produced:

  ```sh
  python two_view_hetero_gat.py \
      --netflows dataset/netflows.csv \
      --graphml  dataset/observed_services.graphml \
      --views both            # or l34 / l7 / none, and --sweep for the full table
  ```

  `netflows.csv` is the **real** L3/4 view and supersedes the derived `flows.csv` from
  `build_dataset.py` (which is aggregated from the same Istio lines as the L7 view and
  so is correlated by construction).

## 6. What was verified

- **Capture works east-west:** a 30 s ambient (loadgenerator-only) capture on `bridge`
  produced 1.8 MB of pcap; Argus extracted 251 clean flows after dropping 14 non-IP /
  Argus-management records.
- **Real pod IPs on both ends:** e.g. `10.244.1.47 → 10.244.1.35`, not the `127.0.0.6`
  the sidecar shows internally.
- **UNSW-style features are populated, not constant:** `sttl` mean 64 (100% non-zero),
  windows ~53k/58k, `spkts` mean ~13, `dur` mean ~2.7 s; `proto` tcp/udp, `state`
  FIN/CON/INT/RST.
- **Model contract holds:** `build_from_capture()` yields a feature matrix aligned with
  the labels and host indices, with binary, multiclass and `--drop_strong` variants all
  loading, and `observed_services.graphml` loading alongside (14 services, 18 edges).

**Not yet run (yours to trigger):** the L3/4-only attack proof — a SYN flood and a
connect flood from an attacker pod (`attack-types.md §8–9`), which should appear in
`netflows.csv` but be absent from the Istio `requests.csv`. The scripts support it; the
automated environment blocked launching the scans here. This is `requirement.md`'s
verification step 2 and is worth capturing for the thesis.

## 7. Limits and cleanup

- **Capture volume:** pcaps rotate every 5 minutes; a sustained flood produces large
  files. The node has ~243 GB free, but watch it and `fetch`/clear between sessions.
- **Leftover pcaps on the node:** `stop` removes the pod but leaves
  `/var/log/pcap-capture` on the minikube node. Clear it with
  `minikube ssh -- sudo rm -rf /var/log/pcap-capture` once you've fetched what you need.
- **Argus↔UNSW parity is close, not exact** (the per-feature mapping isn't fully
  documented upstream). `build_from_capture()` tolerates missing columns rather than
  assuming all are present, so a changed Argus field set won't crash the build.
- **Depends on the L7 side** only for the service graph; the capture itself is
  independent of the `requirement.md` blockers.

## Sources

- [UNSW-NB15 dataset (UNSW)](https://research.unsw.edu.au/projects/unsw-nb15-dataset) — built from pcaps with Argus + Bro/Zeek.
- [CIC-UNSW-NB15 augmentation (UNB)](https://www.unb.ca/cic/datasets/cic-unsw-nb15.html) — re-extracted from the same pcaps with CICFlowMeter, precedent for re-extraction.
- [Argus feature-extraction discussion](https://pairlist1.pair.net/pipermail/argus/2020-August/011272.html) — on the Argus/Bro feature split for UNSW-NB15.
