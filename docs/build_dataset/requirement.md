# Dataset capture readiness: Istio logs and `ai-model/` scripts

Checked on 2026-11-08 against the running cluster: minikube with the Docker runtime, Istio 1.31.1, `default` namespace.

## Summary

| Question | Answer |
| --- | --- |
| Does Istio collect L7 logs? | **Yes.** Every sidecar writes JSON per request, for both HTTP and gRPC. |
| Does Istio collect L4 logs? | **Only partly.** It logs completed TCP connections on non-HTTP ports, and only when they close. It is not a packet or flow capture. |
| Where are the JSON logs saved? | In each `istio-proxy` container's stdout, stored inside the minikube node. They only reach a local file if `02_stream_logs.sh` is running. See [section 3](#3-where-the-json-logs-are-saved). |
| Are the `ai-model/` scripts enough to build the dataset? | **Now yes for an L7 dataset**, after the fixes below. The independent L3/4 view is covered separately by [`l3-capture.md`](./l3-capture.md). |

> **Update 2026-11-08 — blockers 1–4 and 6 fixed (blocker 5 left per request).**
> The capture/parse/label pipeline was corrected and re-verified on real captured logs
> (2,400 records parsed, up from the old inbound-only 2,393 — gateway, passthrough,
> malformed and TCP lines are now kept; UA-tagged probes label as 8 entry rows with no
> fan-out false-positives; flow buckets span 75 s, not thousands). Details per item are
> marked **FIXED** in [§4](#4-audit-of-ai-model) and [§6](#6-recommended-work-in-order).
> What still needs doing by hand: tag attacker traffic during capture (a per-attack
> `User-Agent` or dedicated attacker pod — the parser now keys on it). New companion docs:
> [`attack-types.md`](./attack-types.md), [`l3-capture.md`](./l3-capture.md).

## 1. Project context

- This is Google's Online Boutique, a microservices shop with gRPC between services and HTTP at the `frontend`. It has been extended with a mock `authservice` (`docs/auth-service.md`).
- `ai-model/` holds the thesis work: capture Istio logs from this cluster, turn them into a labeled dataset, and train a two-view (L3/4 + L7) heterogeneous GAT for attack detection.
- `skaffold run` deploys only the app. It does **not** install any of the following, which were applied by hand and exist only in the cluster:
  - Istio
  - the `istio-injection=enabled` namespace label
  - `istio-logging.yaml` and `telemetry.yaml`
  - `frontend-gateway` and its VirtualService

  **Risk:** `minikube delete` removes all of them, and a later `skaffold run` would deploy the app with no logging and no error. **Resolved:** `ai-model/00_setup_istio.sh` rebuilds all of it idempotently (run it after `minikube start`, before `skaffold run`).

## 2. Does Istio collect the logs?

### Configuration: correct

| Check | Result |
| --- | --- |
| Namespace injection | `default` has `istio-injection=enabled`; all 14 app pods are 2/2 Ready |
| Proxy versions | 1.31.1 on the client, control plane and all 15 proxies |
| Mesh config | `json-access-log` provider is present with 26 fields, writing to `/dev/stdout` |
| `Telemetry/json-logging` | Applied mesh-wide from `istio-system` |
| Envoy listeners | HTTP (`http_connection_manager`) and TCP (`tcp_proxy`) chains have the JSON logger attached, with no duplicate logger. One `tcp_proxy` chain on each listener has none. |

### Baseline logs (33 minutes, loadgenerator only)

| Type | Lines | Notes |
| --- | --- | --- |
| L7 HTTP/2 (gRPC) | 113,365 | Includes `path`, `grpc_status`, duration and bytes |
| L7 HTTP/1.1 | 10,234 | Includes method, path, user agent and response code |
| L4 TCP | **2** | Both on `redis-cart`, although `cartservice` uses Redis throughout |

The two L4 lines show the main limitation: Envoy writes a TCP record **when the connection closes**, and no flush interval is set (`accessLogOptions` is empty). A long-lived connection produces nothing until it ends.

### Probe results

I sent a few harmless, tagged requests through each entry path while streaming the logs.

| Probe | Logged? | What the log showed |
| --- | --- | --- |
| HTTP via gateway (`NodePort 32307`) | Yes, at gateway and frontend | Full L7 fields |
| SQLi string in the query string | Yes | The full query is in `path`; bodies are never logged |
| Spoofed `X-Forwarded-For` | Yes | `xff` = `203.0.113.77,10.244.0.1`; `downstream_remote_addr` stays `10.244.0.1` |
| HTTP via `frontend-external` (`NodePort 31802`) | Yes, at frontend only | Skips the gateway |
| **HTTP via `kubectl port-forward`** | **No** | Bypasses the sidecar: the request returned 200 with no log line anywhere |
| Malformed HTTP | Yes | `response_flags=DPE`, `upstream_cluster=null` |
| **TCP connect with no data, on an HTTP port** | **No** | No record at the gateway or the frontend |
| TCP connect to `redis-cart:6379` from a meshed pod | Yes, on both sides | `protocol=null`, `response_code=0` |
| **Connect to a closed pod port from a meshed pod** | Scanner side only | The client's own sidecar accepted it, so the scanner saw "open"; logged as `PassthroughCluster` with nothing logged on the target |
| Failed login to `authservice` (in-cluster) | Yes | `401` is logged; the username is not |

### Not visible to Istio

I did not run these. This follows from how sidecars work:

- **SYN floods and half-open scans:** the kernel handles the handshake, so Envoy never accepts a connection to log.
- **UDP and ICMP:** Istio's sidecar redirection covers TCP only.
- **Packet-level fields:** packet counts, TCP flags, TTL, window size, retransmissions and jitter don't exist in Envoy access logs.

## 3. Where the JSON logs are saved

Istio does not create a log file or a per-attack file, and it does not label anything. When you run an attack script, each proxy on the request's path writes a line to its stdout:

```text
Envoy in the istio-proxy container  ->  /dev/stdout
  -> inside the minikube node:
     /var/log/pods/default_<pod>_<uid>/istio-proxy/0.log
     (symlink to /var/lib/docker/containers/<id>/<id>-json.log)
  -> read with: kubectl logs <pod> -c istio-proxy
  -> saved on your machine ONLY while 02_stream_logs.sh runs:
     <directory you ran it from>/logs/<pod>.log
```

The gateway follows the same pattern under `/var/log/pods/istio-system_istio-ingressgateway-<...>/`.

**Which pod logs the attack depends on how it enters:**

| Attack enters via | Logged by |
| --- | --- |
| Ingress gateway | `istio-ingressgateway`, `frontend`, then every service the request fans out to |
| `frontend-external` NodePort | `frontend`, then fan-out |
| A meshed pod inside the cluster | The attacker pod's sidecar and the target's sidecar |
| `kubectl port-forward` | **Not logged at the target.** Don't use this path for attacks. |

**Why the node copy can't be your dataset:**

- The node files are temporary. They are deleted with the pod, so a redeploy loses them.
- Docker keeps them to `max-size: 100m` with no `max-file` set. `frontend` already writes about 1.3 MB/min at baseline, so it reaches the limit in about 80 minutes, and a flood will get there much sooner.
- Each line is wrapped as `{"log":"<escaped JSON>","stream":"stdout","time":...}`.
- With the Docker driver, the files are inside the minikube container. Use `minikube ssh` to reach them.

Start streaming **before** the attack and treat `logs/` as the only durable copy. `logs/`, `dataset/` and `pods_*.json` are not in `.gitignore`, so add them before committing.

## 4. Audit of `ai-model/`

Originally run from a temporary directory with the repo scripts unchanged. **The
blockers below have since been fixed in the repo scripts** (2026-11-08) and re-verified
on the real captured logs; each row notes the fix.

### Blockers

| # | Location | Problem | Status |
| --- | --- | --- | --- |
| 1 | `02_stream_logs.sh` | **Skipped every app pod.** It looked for `istio-proxy` in `.spec.containers`, but this Istio runs it as a native sidecar in `.spec.initContainers` (`restartPolicy: Always`), with no error. | **FIXED** — now checks `containers` **and** `initContainers`, and exits non-zero if no proxy pods match. Verified: all 15 pods stream. |
| 2 | `build_dataset.py` parser | **Kept only `inbound | `lines**, discarding the highest-signal lines: gateway, malformed (`DPE`),`PassthroughCluster` scans, client-side overload failures. | **FIXED** — keeps all line types tagged with `direction` + `record_type`, keeps gateway/malformed/passthrough, and drops only internal client-side outbound duplicates. Verified: 2,400 records kept vs 2,393 before, now incl. 3 gateway, 2 passthrough, 2 malformed, 3 TCP. |
| 3 | `build_dataset.py` labeling | **Time-window labels marked background traffic as attack**; `x-request-id` can't link fan-out to its entry request (no ID spanned >2 pods). Of 397 "attack" rows, only 4 were real. | **FIXED** — entry-point labeling: an optional `match_ua` column keys the label on the attacker's `User-Agent`; time/`source_ip` windows label entry rows with the attack label and internal fan-out with `<label>_fanout` (excludable). Verified: UA-tagged probes = 8 entry rows, no fan-out false-positives. |
| 4 | `build_dataset.py` bucketing | **Time buckets broke on pandas 3** (ns vs µs assumption): each 5 s bucket became 5,000 s; no pinned pandas. | **FIXED** — `g['ts'].dt.as_unit('s')` before `astype('int64')`; added pinned `requirements.txt`. Verified on pandas 2.3.3 **and** 3.1.1 (bucket span 75 s, 181 flows). |
| 5 | `two_view_hetero_gat.py` | **The model can't read this dataset** (`load_flows` needs UNSW CSVs; no `build_from_capture()`). | **LEFT PER REQUEST** — but in practice already addressed: `build_from_capture()` + `--source capture` were added for the Argus L3/4 path (see [`l3-capture.md`](./l3-capture.md)). Training run still needs `torch`, untested here. |
| 6 | `flows.csv` | **The "L3/4 view" is not L3/4 data** — aggregated from the same L7 lines, correlated by construction. | **ADDRESSED** — a real, independent L3/4 view now comes from a packet capture + Argus (`netflows.csv`); see [`l3-capture.md`](./l3-capture.md). `flows.csv` remains only as a convenience aggregate, now documented as such. |

### Other bugs

| Location | Problem | Status |
| --- | --- | --- |
| `build_dataset.py` service id | `sa` used as service name, but `redis-cart` / `hello-minikube` use the `default` SA → a `default` node in the graph. | **FIXED** — `sa` is used unless it is `default`/`-`, then the pod-name snapshot (app label) is used. |
| `build_dataset.py` IP resolve | Any IP not in the snapshot becomes `external:<ip>`, incl. replaced pods. | **Mitigated** — `01_snapshot_pods.sh` now snapshots all namespaces; keep every snapshot so stale IPs resolve against the right one. A truly-gone pod IP still shows as `external:` (inherent). |
| `build_dataset.py` errors | `n_err` counted only HTTP ≥ 400, missing gRPC errors (which ride on HTTP 200). | **FIXED** — new `is_err` counts HTTP ≥ 400 **or** non-OK `grpc_status`. |
| `build_dataset.py` fields | Dropped `xff`, `user_agent`, `authority`, `request_id`, `response_code_details`, ports. | **FIXED** — all now in `requests.csv` (plus `direction`, `record_type`, `is_entry`, `is_err`). |
| `build_dataset.py` flow label | Bucket took the majority label, losing attacks in mixed buckets. | **FIXED** — any attack request makes the bucket an attack (most-common non-normal label wins). |
| `mark.sh` | Timestamps cut to whole seconds, clipping a window's last requests. | **FIXED** — now millisecond precision (`%3N`); `03_capture_pcap.sh mark` matches. |
| `*.sh` | Scripts weren't executable, so the README's `./01_snapshot_pods.sh` failed. | **FIXED** — `chmod +x` applied to all `ai-model/*.sh`. |
| `02_stream_logs.sh` | The pod list was read once; a pod replaced mid-capture wasn't followed. | **FIXED** — each stream re-attaches while the pod exists (survives a restart). |
| `01_snapshot_pods.sh` | Only one namespace captured, so the gateway pod wasn't in the IP map. | **FIXED** — defaults to all namespaces (gateway included). |
| `two_view_hetero_gat.py` split | The 60/20/20 split is by time; back-to-back attacks can land a class in one split. | **Open (operational)** — repeat and interleave each attack across the session (see the run/label steps in [`attack-types.md`](./attack-types.md)). |

### README statements that don't match this cluster

- **Source IP:** the README says services see the gateway pod's IP. They actually see `10.244.0.1` (port `0`) from `xff`, which is the NodePort's source NAT address. Gateway and NodePort traffic therefore look alike, and the real client IP is hidden. `source_ip` can't separate external attackers.
- **Selftest:** `build_dataset.py --selftest` passes on pandas 3 even with blockers 1, 2 and 4 present, so a pass doesn't show the pipeline works. It doesn't test streaming, gateway lines, L4 lines or time bucketing across a real capture.

### What already works

- The JSON log format parses correctly, and non-JSON startup lines are skipped safely.
- Taking the callee identity from `sa` works for every service except those using the `default` account.
- `observed_services.graphml` gave the real call graph: 14 services and 18 edges, including the `default` and `external:` nodes noted above.
- Kubernetes health checks add no log noise: `authservice` had no JSON lines at baseline, despite its readiness and liveness probes.

## 5. Is it enough for the dataset?

Coverage assumes the blockers above are fixed. It describes what the logs could support, not attacks I ran; only single probes were tested.

| Attack type | Istio logs | Usable after fixes? |
| --- | --- | --- |
| HTTP flood | Per-request L7 lines | Yes. Check for dropped lines at high rates (not tested) |
| SQLi or XSS in URL, path fuzzing | `path`, `response_code`, `user_agent` | Yes |
| SQLi or XSS in POST body | Only the size, no content | Weak, based on size and status only |
| Malformed HTTP | `DPE` lines | Yes, once the parser keeps them |
| Login brute force | `401` bursts | Only from inside the cluster (see below) |
| Port scan | Scanner-side `PassthroughCluster` lines only | Weak, and limited to scans from a meshed pod |
| Slowloris or slow HTTP | Not tested | Unknown; test before relying on it |
| TCP connect flood on an HTTP port | Nothing logged | **No**, needs packet capture |
| SYN flood, UDP or ICMP flood | Nothing logged | **No**, needs packet capture |

**`authservice` gap — FIXED (2026-11-08).** It used to have no route and no traffic, so a model would learn "any call to authservice = attack." Now:
- `/login` is mesh-routed to `authservice:8080` on both the internal `frontend` host and the ingress gateway (`istio-manifests/frontend.yaml`, `istio-manifests/frontend-gateway.yaml`), so it is reachable **in-cluster and externally** (external brute force is now possible). Verified live: valid → 200+token, wrong → 401, malformed → 400; the shopping path (`/`, `/product/...`) is unchanged.
- The loadgenerator now has a `login` task (valid sample creds) giving a **normal** baseline for authservice. This takes effect after the loadgenerator image is rebuilt (`skaffold run`).

**Conclusion:** after the fixes, the logs can support an **L7 application-attack dataset**. They can't support a real two-view L3/4 + L7 dataset, because the L4 side would be missing or derived from L7.

## 6. Recommended work, in order

**Required before capturing**

1. ✅ **Done** — `02_stream_logs.sh` checks `initContainers` and errors if no proxy pods match.
2. ✅ **Done** — bucket calculation fixed; pinned `requirements.txt` added.
3. ✅ **Done** — parser keeps all line types with `direction`/`record_type` + the dropped fields, keeps gateway lines, drops only internal outbound duplicates.
4. ✅ **Done (code)** — entry-point labeling via the `match_ua` column; fan-out labeled `<label>_fanout`. **Operational part still on you:** actually set a per-attack `User-Agent` (or use a dedicated attacker pod) when you run the attacks, so the labels have something to key on.
5. ✅ **Done** — `mark.sh` / `03_capture_pcap.sh mark` emit millisecond precision. **On you:** drive attacks via the gateway or a meshed pod, never `port-forward`.
6. ✅ **Done** — `ai-model/00_setup_istio.sh` installs Istio with the JSON access-log meshConfig (`istioctl install -f istio-logging.yaml`), labels the namespace, applies `telemetry.yaml` and the ingress gateway/VirtualServices, and verifies. Idempotent; validated by rendering the operator (126 resources, access-log config present) and server dry-run of every manifest (all "unchanged" vs the live cluster).

**Required for the two-view design**

1. ✅ **Done** — independent L3/4 source implemented with a node packet capture + **Argus** (not CICFlowMeter, for UNSW-feature comparability): `capture-daemonset.yaml`, `03_capture_pcap.sh`, `04_pcap_to_flows.sh` → `netflows.csv`. See [`l3-capture.md`](./l3-capture.md). Makes SYN/UDP/connect floods visible.
2. ✅ **Decided** — kept as two separate tables fused in-model (no 5-tuple correlation through Istio NAT); see [`l3-capture.md §5`](./l3-capture.md).
3. ✅ **Done (code)** — `build_from_capture()` + `--source capture` added. **On you:** repeat/interleave attacks across the session so each class lands in every split.

**Optional / still open**

 1. ⬜ Flush long TCP connection logs with an `EnvoyFilter` (`access_log_flush_interval`) — not done.
 2. ⬜ Set `externalTrafficPolicy: Local` on the gateway Service to try to preserve the client IP — not done.
 3. ✅ **Done** — service-name fallback and gRPC error counting fixed (§4 Other bugs). `external:` naming for truly-gone pods is inherent.
 4. ✅ **Done** — `authservice` now has a `/login` route (internal + gateway) and a loadgenerator `login` baseline task; see the authservice note above. Live-verified for routing; baseline traffic needs a `skaffold run`.

## 7. Test limits

- **Capture size:** one full 75-second capture (plus an earlier run that caught only the gateway) and 33 minutes of existing logs, so the percentages describe this run rather than a full dataset.
- **Probes:** each was a single request or connection. I ran no real attack tools and no high-rate traffic, so log loss, proxy overload and `kubectl logs -f` behaviour at rotation are untested.
- **Fixes applied to repo scripts:** blockers 1–4/6 and the other bugs were fixed in the actual `ai-model/` scripts and re-verified — the selftest passes on pandas 2.3.3 and 3.1.1, and a real run on the captured logs produced the numbers in the §4 "Status" column. The model *training* run (`--source capture`) still needs `torch`/`torch_geometric`, which aren't installed here, so that step is validated only at the data-loading level (via stubbed imports).
- **Traffic added:** the probes added a small amount of tagged traffic, including two failed logins, to the cluster's logs. They appear with user agents starting `probe-`, and the raw TCP and malformed probes have no user agent, around `2026-11-07T18:36` and `18:38` UTC.
