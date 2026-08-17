import hashlib
import hmac
import json
import uuid

import pytest
from fastapi import HTTPException

from app.integrations.nagecen import (
    handoff_context_response,
    HandoffInput,
    token_hash,
    validate_handoff_consistency,
    verify_handoff_signature,
)


def handoff_payload() -> dict:
    product_id = "123"
    return {
        "version": "1",
        "jti": str(uuid.uuid4()),
        "intent": "verify_and_scan",
        "product": {
            "id": product_id,
            "status": "draft",
            "owner_subject": "42",
            "url": "https://example.com/app/",
        },
        "ownership": {"status": "unverified", "verified_url": None, "verified_at": None},
        "return_context": {"type": "product_draft", "id": product_id},
    }


def test_verifies_signature_over_exact_raw_body(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "a" * 32
    monkeypatch.setenv("NAGECEN_TO_SECURITY_HMAC_SECRET", secret)
    monkeypatch.setenv("NAGECEN_TO_SECURITY_KEY_ID", "local-v1")
    raw_body = json.dumps(handoff_payload(), separators=(",", ":")).encode()
    timestamp = "1000"
    signature = "sha256=" + hmac.new(
        secret.encode(), timestamp.encode() + b"." + raw_body, hashlib.sha256
    ).hexdigest()

    verify_handoff_signature(raw_body, timestamp, signature, "local-v1", now=1000)

    with pytest.raises(HTTPException) as error:
        verify_handoff_signature(raw_body + b" ", timestamp, signature, "local-v1", now=1000)
    assert error.value.detail["code"] == "invalid_signature"


def test_rejects_expired_handoff_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "b" * 32
    monkeypatch.setenv("NAGECEN_TO_SECURITY_HMAC_SECRET", secret)
    monkeypatch.setenv("NAGECEN_TO_SECURITY_KEY_ID", "local-v1")
    raw_body = b"{}"
    signature = "sha256=" + hmac.new(
        secret.encode(), b"1000." + raw_body, hashlib.sha256
    ).hexdigest()

    with pytest.raises(HTTPException) as error:
        verify_handoff_signature(raw_body, "1000", signature, "local-v1", now=1301)
    assert error.value.detail["code"] == "signature_timestamp_out_of_range"


def test_draft_requires_product_draft_return_context() -> None:
    payload = handoff_payload()
    payload["return_context"]["type"] = "mypage"

    with pytest.raises(HTTPException) as error:
        validate_handoff_consistency(HandoffInput.model_validate(payload))
    assert error.value.detail["code"] == "invalid_return_context"


def test_return_context_id_must_match_product_id() -> None:
    payload = handoff_payload()
    payload["return_context"]["id"] = "999"

    with pytest.raises(HTTPException) as error:
        validate_handoff_consistency(HandoffInput.model_validate(payload))
    assert error.value.detail["code"] == "product_id_mismatch"


def test_handoff_tokens_are_hashed_before_storage() -> None:
    assert token_hash("temporary-token") == hashlib.sha256(b"temporary-token").hexdigest()
    assert "temporary-token" not in token_hash("temporary-token")


def test_draft_return_url_contains_the_exact_draft_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NAGECEN_FRONTEND_URL", "http://localhost:5173/nagecen")
    context = handoff_context_response({
        "id": uuid.uuid4(),
        "intent": "verify_and_scan",
        "product_id": "123",
        "product_status": "draft",
        "product_url": "https://example.com/app/",
        "normalized_url": "https://example.com/app/",
        "target_origin": "https://example.com",
        "target_base_path": "/app/",
        "return_context_type": "product_draft",
        "return_context_id": "123",
        "status": "active",
    })

    assert context.return_url == (
        "http://localhost:5173/nagecen/post?draft=123&security_return=completed"
    )
