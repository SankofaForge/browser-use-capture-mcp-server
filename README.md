# Browser Use capture MCP server

This local stdio MCP server is the Browser Use adapter boundary for the
design-inspiration capture contract. It exposes only `check_capture_gpu` and
`capture_site_motion`. The required runtime keeps workflow control and MCP
stdio local, then invokes the pinned Browser Use worker on the rented Linux GPU
runner through the current SSH endpoint provided by Vast. Browser Use and
Chrome do not run on the local workflow host.

The latest live probe passed CDP startup, page evaluation, viewport and
reduced-motion control, jank collection, WebM recording, cleanup, and hardware
WebGL.
It did not prove that every Chrome network path uses the SOCKS proxy. The
compatibility result now reports CPU behavior, GPU support, and egress status
separately. Egress remains unverified, so the adapter must not issue a
`gpu_check_id` or claim complete evidence.

The adapter is intentionally fail-closed. Browser Use releases have changed
their session and recording APIs, and this project must not create a WebM or
jank manifest from an unverified API. The exact locked release must pass the
compatibility spike; there is no manual compatibility override.

The project pins `browser-use[video]==0.13.10` in `pyproject.toml` and
`uv.lock`. Set `BROWSER_USE_CHROMIUM_PATH` in the remote worker environment to
the absolute path of a provisioned, executable, non-Snap Chrome/Chromium binary
on the GPU runner. The current real Chrome path is `/opt/google/chrome/chrome`.
The earlier `/usr/bin/chromium-browser` path is a Snap installation shim and
`/usr/bin/google-chrome` is a launcher chain; reject both before
`BrowserSession` starts. Do not allow automatic browser downloads. The remote
worker disables Browser Use telemetry, cloud sync, and release checks. Chrome
starts on a local `data:` document so Browser Use's about:blank logo overlay
does not request an unapproved host. Provide `VAST_API_KEY` to the local
adapter only through its secret-aware environment; never put secret values in
workflow configuration or diagnostics. Resolve the SSH host and port
dynamically from Vast instead of hard-coding an instance endpoint.

The compatibility report treats `domain-not-approved` outcomes as proxy
denials, not CPU-function failures. It records them under
`egressPolicy.blockedDestinations`. Private destinations, proxy errors, and
unapproved successful connections still block the egress result. The report
also separates observations made before and after fixture navigation. These
phases do not identify request initiators, URL paths, or Chrome services.

The proxy's negative-control checks do not prove that all Chrome traffic uses
the proxy. The result therefore keeps `egressPolicy.status` unverified until a
browser-wide egress boundary is verified. It also reports Safe Browsing and
component-update reachability as not assessed. No `gpu_check_id` is issued
while either fact remains unresolved.

A bounded runtime sweep on 2026-09-22 did not find a passing alternative.
Chrome for Testing Stable 154.0.8037.57 passed the browser and hardware-WebGL
checks but triggered five denied Google service hosts. Its headless shell
failed the fixture-title and hardware-WebGL checks. Microsoft Edge Stable
153.0.4234.48 passed the page, viewport, reduced-motion, jank, recording,
cleanup, and GPU checks, but triggered denied requests to `edge.microsoft.com`
on ports 80 and 443, `www.bing.com`, and
`nav-edge.smartscreen.microsoft.com`. No egress rule or default browser
changed. Capture remains blocked.

The launch-argument audit found both `--disable-background-networking` and
`--disable-component-update` in the initial source. The worker and probe now
omit these switches, and regression tests keep them out. Chromium documents
the first as disabling background network subsystems; it also disables Safe
Browsing auto-updates. The second stops component-update registration. Do not
restore either switch to suppress denied requests.

Run the locked compatibility probe on the remote GPU runner with:

```text
uv run --locked python scripts/verify_compatibility.py
```

An explicitly approved egress diagnostic can use
`--reviewed-egress-experiment`. It adds only `www.gstatic.com:443` and
`update.googleapis.com:443` to that probe's in-process SOCKS policy. The
exception is exact-host only, expires no later than 60 minutes after proxy
creation, and ends earlier when the probe exits. The probe itself has a
110-second deadline; the bounded Vast invocation stops it after 120 seconds.
This does not change the runner's network firewall or the normal capture
proxy: `capture_worker.py` never enables the experiment. Its result is marked
diagnostic-only and cannot authorize capture or issue a `gpu_check_id`. Do not
add hosts through command-line values or configuration.

The proxy records a bounded summary of destination hostname, port, and
connection outcome. The probe also records whether an observation occurred
before or after fixture navigation. It does not inspect tunneled payloads,
collect URL paths or HTTP methods, or observe request initiators. HTTPS
metadata would require TLS interception, which is outside this diagnostic.
The probe does not collect raw NetLog data. Do not infer a request source from
its phase alone.

The approved diagnostic ran once on 2026-09-23. Both candidate hosts connected,
but CPU compatibility remained blocked by other destinations, including
`clients2.google.com`, `www.google.com`, `accounts.google.com`,
`android.clients.google.com`, `edgedl.me.gvt1.com`, and `dl.google.com`. GPU and
hardware-backed WebGL passed. The probe remained diagnostic-only, issued no
`gpu_check_id`, and did not change the ordinary proxy policy. See the [egress
proposal and result](../../agent-infrastructure/knowledge/browser-use-capture-egress-proposal.md).

The probe must launch Chrome, wait for its loopback CDP endpoint, and attach
`BrowserSession`. It must verify page evaluation, viewport control,
reduced-motion emulation, jank instrumentation, domain enforcement, recording,
WebM validation, and cleanup. The JSON result must report separate CPU, GPU, and
egress results. It must retain the executable path and browser versions, even
when a gate fails. A CPU or GPU pass cannot override an unverified egress
boundary. Test each blocked state and preserve its failure reason.

The CPU gate checks browser functions. The GPU gate requires a working
`nvidia-smi` and a hardware-backed WebGL renderer. SwiftShader and other
software renderers fail. The egress gate must verify the browser-wide network
boundary and required browser security-service reachability. A SOCKS
negative-control result or successful TCP connection alone cannot pass that
gate. A fresh
`gpu_check_id` requires all three results to pass and must bind to the runner,
browser executable, and Browser Use release.

## Recover from a startup timeout

1. Resolve the active Vast-managed SSH endpoint and confirm the configured
   instance is reachable.
2. On the runner, verify the configured path is absolute and executable, then
   run that exact path with `--version`. Provision real Chrome if needed; do
   not use `/usr/bin/chromium-browser` or another Snap shim.
3. Start Chrome explicitly with a run-specific temporary profile and a
   loopback debugging port. Wait for `/json/version` to report CDP readiness,
   then attach Browser Use using that CDP URL. Do not rely on Browser Use's
   local executable-discovery startup path.
4. Run the locked CPU and GPU/WebGL checks. Review the egress result separately.
   A SOCKS negative-control pass does not prove that all browser traffic uses
   the proxy or verify required browser security-service reachability. A TCP
   connection alone does not prove that a service works. Record the JSON result
   and repair the reported cause before retrying.
5. Only after CPU, GPU, and browser-wide egress checks pass may
   `check_capture_gpu` issue a fresh, runner-bound `gpu_check_id`. No manual
   compatibility override or automatic `site-motion-capture` fallback is
   permitted.

Missing browser, SSH or startup timeout, missing GPU, software WebGL renderer,
recording or jank failure, consent uncertainty, domain violation, timeout,
cleanup failure, or artifact mismatch remains `blocked` or `partial`.

The server validates HTTP(S) URLs, rejects private-address resolution,
requires explicit approval for `consent_mode: "accept"`, requires all
selectors for granular consent, isolates artifact names, hashes artifacts,
and requires `ffprobe` to validate non-empty WebM files. It does not use
Browser Use Cloud, persistent user profiles, raw filesystem tools, or the
autonomous Browser Use agent path.

## Runtime

The Vast bridge provisions the locked `uv` environment in its runner runtime
directory, separate from the source checkout. Use `uv sync --locked --extra test`
when provisioning that runtime; do not install dependencies into the source
checkout.
Start the local stdio adapter with:

```text
uv run browser-use-capture-mcp
```

The dependency pin is not proof that the compatibility matrix has passed.

## Acceptance boundary

Runner provisioning, a passing CPU probe, and a visible GPU each establish only
their own checks. Full acceptance also requires consent and animated/WebGL
fixtures across desktop/full, desktop/reduced, mobile/full, and mobile/reduced
cells; distinct, non-empty, hash-valid WebM and jank artifacts; unchanged
downstream schema validation; and verified cleanup after success and every
failure mode. Performance acceptance compares three cold and five warm
four-cell runs against the existing baseline, with each cell within its
current timeout and p95 duration and peak memory no more than 20% worse.
Until those results are recorded, do not claim complete capture evidence.

The legacy `site-motion-capture` backend remains an explicit manual rollback
during acceptance. It is not an automatic fallback.
