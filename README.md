# Browser Use capture MCP server

This local stdio MCP server exposes `check_capture_gpu` and
`capture_site_motion` for design-inspiration captures. The local adapter
connects to a rented Linux GPU runner over its current Vast SSH endpoint;
Browser Use and Chrome run on that runner.

Chrome records video through the Chrome DevTools Protocol screencast API
(`Page.startScreencast` / `Page.stopScreencast`). As the browser renders updates,
frames arrive event-driven via `Page.screencastFrame`, are acknowledged with
`Page.screencastFrameAck`, and are streamed into an FFmpeg frame pump targeting 30
frames per second. FFmpeg converts the intermediate capture into high-quality
WebM (VP9); the recorder does not poll discrete screenshots or drop idle pauses.
The compatibility probe tests this same screencast recording path.

Screencast recording captures at 30 frames per second. Set `smooth_scroll=true` to
use one continuous Chrome scroll gesture (`Input.synthesizeScrollGesture`) at
`scroll_speed` pixels per second (default 500, range 100–2000). This mode ignores
step and pause settings, records observed scroll positions, and checks consent
during the gesture. It fails without a wheel-event fallback when the gesture cannot
complete.

Both tools accept `dry_run` (default `false`). With `dry_run=true`,
`check_capture_gpu` lists its planned checks without contacting the runner.
`capture_site_motion` validates the inputs and local artifact targets, then
returns the capture settings and planned file names. It does not start a runner,
send network requests, or write files. A dry run does not verify GPU support,
reach the target site, or confirm consent behavior.

The compatibility probe checks the pinned Browser Use API, Chrome startup and
CDP attachment, page evaluation, viewport and reduced-motion controls, jank
collection, WebM recording, cleanup, and hardware-backed WebGL. A fresh
`gpu_check_id` requires a passing CPU and GPU probe. It binds to the runner,
browser executable, and pinned Browser Use release. There is no manual
compatibility override.

The project pins `browser-use[video]==0.13.10` in `pyproject.toml` and
`uv.lock`. Set `BROWSER_USE_CHROMIUM_PATH` on the runner to an absolute,
executable, non-Snap Chrome/Chromium binary. The current real Chrome path is
`/opt/google/chrome/chrome`. The adapter starts Chrome explicitly on a
run-scoped profile and loopback CDP port, then attaches Browser Use. Automatic
browser downloads are disabled. Provide `VAST_API_KEY` only through the local
secret-aware environment; resolve the SSH endpoint dynamically.

Run the locked compatibility probe on the GPU runner with:

```text
uv run --locked python scripts/verify_compatibility.py
```

Captures run as a dedicated nonroot user. The adapter accepts HTTP(S) URLs,
including local and private addresses, uses isolated profiles, and validates
consent, recording, jank, artifact hashes, and cleanup. It does not create an
egress attestation or require a proxy or network namespace. Chrome may make
ordinary service requests during a capture.

For an explicitly authorized disposable runner, set
`BROWSER_USE_DISABLE_SANDBOX=1` on the local adapter process. The bridge passes
this setting to the compatibility probe and capture worker. Chrome then uses
`--no-sandbox`. Other values keep sandboxing enabled. Remove the setting when
the temporary session ends, and enforce the runner's approved lifetime through
its rental teardown process.

## Recover from a startup timeout

1. Resolve the active Vast-managed SSH endpoint and confirm the runner is reachable.
2. Verify that `BROWSER_USE_CHROMIUM_PATH` is an absolute executable and run
   that binary with `--version`.
3. Start Chrome with a run-specific profile and loopback CDP port. Wait for
   `/json/version`, then attach Browser Use.
4. Run the CPU and hardware WebGL checks, record the JSON result, and fix any
   reported failure before retrying.

Missing browser, SSH or startup timeout, missing GPU, software WebGL renderer,
recording or jank failure, consent uncertainty, domain violation, timeout,
cleanup failure, or artifact mismatch remains `blocked` or `partial`.

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
