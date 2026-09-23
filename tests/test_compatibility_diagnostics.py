from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import verify_compatibility as compatibility
from verify_compatibility import _attach_probe_metadata


def test_default_probe_metadata_has_no_temporary_egress_hosts():
    result = _attach_probe_metadata({"status": "blocked"}, False)

    assert result["temporaryEgressApproval"] == {
        "enabled": False,
        "scope": "single compatibility-probe process",
        "hostnames": [],
        "port": 443,
        "maxLifetimeSeconds": 0,
        "probeDeadlineSeconds": 110,
    }
    assert result["requestMetadataLimitations"]["rawNetLogCaptured"] is False
    assert result["requestMetadataLimitations"]["httpsMetadataRequiresTlsInterception"] is True
    assert result["requestMetadataLimitations"]["notCollectedFields"] == [
        "URL path",
        "HTTP method",
        "request initiator",
    ]
    assert "captureAuthorized" not in result


def test_temporary_egress_probe_never_authorizes_capture():
    result = _attach_probe_metadata({"status": "verified"}, True)

    assert result["status"] == "blocked"
    assert result["diagnosticOnly"] is True
    assert result["captureAuthorized"] is False
    assert result["failureReason"] == "temporary egress experiment cannot authorize capture"
    assert result["temporaryEgressApproval"]["hostnames"] == [
        "update.googleapis.com",
        "www.gstatic.com",
    ]
    assert result["temporaryEgressApproval"]["maxLifetimeSeconds"] == 3600
    assert result["temporaryEgressApproval"]["probeDeadlineSeconds"] == 110


def test_timed_out_experiment_is_blocked_and_cannot_authorize_capture(monkeypatch):
    async def never_finishes(*, reviewed_egress_experiment: bool):
        await asyncio.sleep(1)

    monkeypatch.setattr(compatibility, "verify", never_finishes)
    monkeypatch.setattr(compatibility, "VERIFY_TIMEOUT_SECONDS", 0.001)

    result = asyncio.run(
        compatibility._verify_with_signal_cleanup(reviewed_egress_experiment=True)
    )

    assert result["status"] == "blocked"
    assert result["cpu"]["status"] == "blocked"
    assert result["gpu"]["status"] == "blocked"
    assert result["failureReason"] == (
        "compatibility probe exceeded its 0.001-second deadline"
    )
    assert result["diagnosticOnly"] is True
    assert result["captureAuthorized"] is False
    assert result["temporaryEgressApproval"]["probeDeadlineSeconds"] == 0.001


def test_cleanup_finishes_after_repeated_cancellation():
    async def run_cancellation_scenario():
        cleanup_started = asyncio.Event()
        allow_cleanup_to_finish = asyncio.Event()
        cleanup_finished = asyncio.Event()

        async def cleanup():
            cleanup_started.set()
            await allow_cleanup_to_finish.wait()
            cleanup_finished.set()

        cleanup_task = asyncio.create_task(compatibility._await_cleanup(cleanup()))
        await cleanup_started.wait()
        cleanup_task.cancel()
        await asyncio.sleep(0)
        cleanup_task.cancel()
        allow_cleanup_to_finish.set()

        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("cleanup wrapper should preserve cancellation")

        assert cleanup_finished.is_set()

    asyncio.run(run_cancellation_scenario())
