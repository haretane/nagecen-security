import hashlib
import hmac

from app.integrations.webhook import RETRY_DELAYS, sign_webhook


def test_webhook_signature_uses_exact_body() -> None:
    body = b'{"version":"1"}'
    timestamp = "1000"
    secret = "s" * 32

    signature = sign_webhook(body, timestamp, secret)
    expected = "sha256=" + hmac.new(
        secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256
    ).hexdigest()

    assert signature == expected


def test_webhook_retry_schedule_matches_contract() -> None:
    assert RETRY_DELAYS == (10, 60, 300, 1800)
