from app.api.routes.scan_jobs import cancellation_error_for_status


def test_queued_scan_can_be_cancelled() -> None:
    assert cancellation_error_for_status("queued") is None


def test_running_scan_waits_for_safe_completion() -> None:
    error = cancellation_error_for_status("running")

    assert error is not None
    assert error[0] == "scan_already_running"


def test_finished_scan_cannot_be_cancelled_again() -> None:
    for status in ("completed", "failed", "cancelled"):
        error = cancellation_error_for_status(status)
        assert error is not None
        assert error[0] == "scan_not_cancellable"
