# Attack types to run for dataset collection

Companion to [`requirement.md`](./requirement.md). This lists the attack types worth
running against **your own** Online Boutique cluster to produce labeled malicious
traffic, which layer each one targets, and whether the Istio access logs from
`requirement.md` can actually see it.

**Scope and safety.** Everything here is for your own minikube cluster for thesis
data collection. Run each attack from its own machine or an attacker pod you
control, against the Istio ingress (`NodePort 32307`) or from a meshed pod —
never through `kubectl port-forward` (it bypasses the sidecar and logs nothing).
Keep a few minutes of clean `loadgenerator` traffic between runs. These tools can
knock the demo over; that is fine for a lab, but do not point them at anything you
do not own.

## Layer cheat-sheet

| Layer | What it means here | Can Istio access logs see it? |
| --- | --- | --- |
| L3 (network) | IP: ICMP floods, spoofing | **No** — sidecar redirects TCP only |
| L4 (transport) | TCP/UDP: SYN floods, port scans, connection floods | **Partly** — only completed TCP connections that reach Envoy; nothing kernel-handled |
| L7 (application) | HTTP/gRPC: request floods, injection, brute force, fuzzing | **Yes** — one JSON line per request |

The two-view model wants both an L3/4 view and an L7 view. Istio gives you a strong
L7 view and a weak L4 view. For the L3/4 attacks below you need the independent
packet capture (`tcpdump` → CICFlowMeter) recommended in `requirement.md §6`;
without it, the L3/4-only attacks will be invisible or appear only as a gap.

## Recommended attacks

Ordered by how well this setup captures them. Suggested `label` values are for
`labels.csv` / the entry-point labeling in `requirement.md §6`.

### 1. HTTP request flood — **L7** (best supported)
- **Target:** `frontend` via the ingress gateway.
- **Tooling:** `wrk2`, `hey`, `locust`, or `ab` at high concurrency and a fixed rate.
- **Istio signal:** a burst of L7 lines, same `path`, high requests/sec from one
  source, rising `duration_ms`, and `response_flags` such as `UO`/`UH`/`UT` once
  services saturate. This is the cleanest attack-vs-normal contrast you can get.
- **Label:** `http_flood`. **Also capture** a lower-rate run so the model can't
  just threshold on volume.
- **Watch:** check for dropped log lines at high rates (untested in `requirement.md`).

### 2. Path / endpoint fuzzing and forced-browsing — **L7**
- **Target:** `frontend` routes (`/product/<id>`, `/cart`, `/setCurrency`).
- **Tooling:** `ffuf`, `gobuster`, or OWASP ZAP spider against your ingress.
- **Istio signal:** many distinct `path` values, a spike in `404`/`500`, odd
  `user_agent`. `path` and `response_code` are fully logged.
- **Label:** `fuzzing`.

### 3. Injection attempts in the URL — **L7**
- **Target:** `frontend` query strings and path parameters.
- **Tooling:** ZAP active scan, `sqlmap`, or `nikto` against your ingress. (Online
  Boutique has no SQL backend, so these won't *succeed* — that's fine; you're
  labeling the *attempt*, not a breach.)
- **Istio signal:** the full query string is in `path` (confirmed: the SQLi probe
  in `requirement.md` logged `id=1' OR 1=1--`). **Request bodies are not logged**,
  so POST-body injection shows up only as size + status.
- **Label:** `injection`.

### 4. Malformed / protocol-violating HTTP — **L7**
- **Target:** ingress or `frontend`.
- **Tooling:** raw sockets, `nc`, malformed `curl`, or a fuzzer like `boofuzz`.
- **Istio signal:** `response_flags=DPE`, `response_code=400`,
  `response_code_details=http1.codec_error`, `upstream_cluster=null` (confirmed in
  `requirement.md`). The parser must be fixed to keep these (blocker 2).
- **Label:** `malformed_http`.

### 5. Login brute force — **L7**
- **Target:** `/login` → `authservice:8080`.
- **Reachability (updated 2026-11-08):** `/login` is now mesh-routed to authservice on
  both the internal `frontend` host **and** the ingress gateway, so brute force works
  **externally** (`http://<gateway>/login`) *and* in-cluster. The loadgenerator also
  sends valid logins, so authservice has a **normal baseline** to contrast against.
- **Tooling:** `hydra`, `patator`, or a short script looping credentials against the
  gateway's `/login` (or from a meshed pod). Sample valid accounts are in
  `src/authservice/data/users.json` — use wrong passwords for the attack.
- **Istio signal:** bursts of `POST /login` with `response_code=401` (confirmed);
  valid baseline logins are `200`. Usernames and passwords are **not** logged.
- **Label:** `brute_force` (wrong-password burst) vs the `normal` valid-login baseline.

### 6. Slow HTTP (Slowloris / slow POST) — **L7, needs verification**
- **Target:** ingress / `frontend`.
- **Tooling:** `slowhttptest`, `slowloris`.
- **Istio signal:** expected to show long `duration_ms` and held connections, but
  this was **not tested** in `requirement.md` — Envoy may buffer or time out the
  request before logging. Verify it produces usable lines before relying on it.
- **Label:** `slow_http`.

### 7. TCP port scan — **L4 (weak)**
- **Target:** pod IPs / service ports from a meshed attacker pod.
- **Tooling:** `nmap` (connect scan `-sT`), `masscan`.
- **Istio signal:** weak and one-sided. A connect to a *closed* pod port is
  accepted by the scanner's **own** sidecar and logged as `PassthroughCluster` on
  the scanner side, with nothing on the target (confirmed). SYN/half-open scans
  (`nmap -sS`) are kernel-handled and **invisible** to Istio.
- **Label:** `port_scan`. Needs the packet capture to be meaningful.

### 8. TCP connection flood on an HTTP port — **L4, not visible**
- **Tooling:** `hping3 --flood`, many bare TCP connects.
- **Istio signal:** connect-only sockets that send no data produced **no log line**
  (confirmed). Requires packet capture.
- **Label:** `conn_flood`.

### 9. SYN flood — **L3/L4, not visible**
- **Tooling:** `hping3 -S --flood`.
- **Istio signal:** none — the kernel handles the handshake, Envoy never accepts a
  connection to log. **Only** captured by `tcpdump`.
- **Label:** `syn_flood`.

### 10. UDP / ICMP flood — **L3/L4, not visible**
- **Tooling:** `hping3 --udp` / `--icmp`.
- **Istio signal:** none — sidecar redirection is TCP-only. **Only** captured by
  `tcpdump`.
- **Label:** `udp_flood` / `icmp_flood`.

## Suggested minimum set for a usable dataset

- **L7-only dataset (works today, after the `requirement.md` fixes):** #1, #2, #3,
  #4, #5, plus a verified #6. This is a solid application-attack dataset.
- **Add for the real two-view L3/4 design (needs `tcpdump` capture):** #7, #8, #9,
  #10 — these are the ones that give the L3/4 view something the L7 view does not
  already contain, which is the whole point of the two-view comparison.

## How to run and label cleanly

**The easy way:** `ai-model/05_run_attacks.sh` automates everything below — it starts
the captures, runs the attacks from an unmeshed attacker pod in clean windows, writes
`labels.csv` for you, and tears down. See [`attack-simulation.md`](./attack-simulation.md).
The manual steps below are what it does under the hood:

1. Start `02_stream_logs.sh` (fixed per blocker 1) **before** any attack, and start
   `tcpdump` on the minikube node if you want the L3/4 attacks.
2. Snapshot pod IPs (`01_snapshot_pods.sh`) at the start and after any restart.
3. Run **one** attack type per window, with nothing else generating load except the
   baseline `loadgenerator`, and tag attacker requests at the entry point (a unique
   `User-Agent` or a dedicated attacker pod — see `requirement.md §6`).
4. Record precise start/end times (fix `mark.sh` to keep sub-second precision).
5. Leave a clean gap, then run the next type. Repeat and interleave each type across
   the session so every class lands in all of the train/val/test splits.
