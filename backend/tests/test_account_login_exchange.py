import asyncio
import dataclasses
import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime

import aiohttp
import pytest
from aiohttp import web

from app.account_login.config import LoginSettings
from app.account_login.protocol import LoginError
from app.account_login.service import exchange_code


def configuration() -> LoginSettings:
    return LoginSettings("http://localhost:5174", "http://localhost:5173/nagecen/security-login",
                         "http://localhost:8080/api/exchange_security_login_code.php",
                         "http://localhost:5173/nagecen/", "http://localhost:5174/auth/nagecen/callback",
                         "isolated-test-key", "synthetic-exchange-test-" + "x" * 32)


async def run_exchange_case(case: str) -> tuple:
    settings = configuration()
    expected_subject, expected_login = uuid.uuid4(), uuid.uuid4()
    requests, traps = [], []

    async def handler(request):
        raw = await request.read()
        body = json.loads(raw)
        timestamp = request.headers["X-Security-Login-Timestamp"]
        expected = "sha256=" + hmac.new(settings.secret.encode(),
                                        b"nagecen-security-login-v1." + timestamp.encode() + b"." + raw,
                                        hashlib.sha256).hexdigest()
        assert hmac.compare_digest(expected, request.headers["X-Security-Login-Signature"])
        assert request.headers["X-Security-Login-Key-Id"] == settings.key_id
        assert body["code"] == "C" * 43 and body["code_verifier"] == "V" * 43
        assert body["redirect_uri"] == settings.callback_url and body["client_id"] == "nagecen-security"
        requests.append(body["request_id"])
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        response = {"status": "success", "version": "1", "request_id": body["request_id"],
                    "login_id": str(expected_login), "issuer": settings.issuer, "audience": "nagecen-security",
                    "subject": str(expected_subject), "issued_at": now, "validated_at": now}
        if case == "redirect": return web.Response(status=307, headers={"Location": "/trap"})
        if case in {"invalid_grant", "expired_code", "reused_code"}:
            return web.json_response({"message": "must not be echoed"}, status=400)
        if case in {"invalid_client", "signature_rejected"}:
            return web.json_response({"message": "must not be echoed"}, status=401)
        if case == "server_error": return web.Response(text="must not be echoed", status=500)
        if case == "content_type": return web.Response(text=json.dumps(response))
        if case == "malformed": return web.Response(body=b"{invalid", content_type="application/json")
        if case == "too_large": return web.Response(body=b" " * 8193, content_type="application/json")
        if case == "wrong_issuer": response["issuer"] = "https://other.example/"
        if case == "wrong_request": response["request_id"] = str(uuid.uuid4())
        if case == "wrong_subject": response["subject"] = "42"
        return web.json_response(response)

    async def trap(request):
        traps.append(True)
        return web.Response(status=500)

    server = web.Application()
    server.router.add_post("/exchange", handler)
    server.router.add_route("*", "/trap", trap)
    runner = web.AppRunner(server, access_log=None)
    await runner.setup()
    # New localhost-only, ephemeral test endpoint; never call the real main app.
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    test_settings = dataclasses.replace(settings, exchange_url=f"http://127.0.0.1:{port}/exchange")
    try:
        try:
            result = await exchange_code(test_settings, "C" * 43, "V" * 43)
        except LoginError as error:
            result = error
        assert len(requests) == 1  # No automatic retry of a single-use code.
        assert traps == []  # Do not follow a redirect with code/verifier/headers.
        return result, expected_subject, expected_login
    finally:
        await runner.cleanup()


def test_actual_http_exchange_sends_signed_raw_bytes_once():
    result, subject, login_id = asyncio.run(run_exchange_case("success"))
    assert result == (subject, login_id)


@pytest.mark.parametrize("case", ["redirect", "invalid_grant", "expired_code", "reused_code",
                                 "invalid_client", "signature_rejected", "server_error",
                                 "content_type", "malformed", "too_large", "wrong_issuer",
                                 "wrong_request", "wrong_subject"])
def test_actual_http_exchange_rejects_untrusted_responses(case):
    result, _, _ = asyncio.run(run_exchange_case(case))
    assert isinstance(result, LoginError)
    assert result.status == (400 if case in {"invalid_grant", "expired_code", "reused_code"} else 503)
    assert "must not be echoed" not in result.message


def test_timeout_is_sanitized_and_not_retried(monkeypatch):
    calls = []

    class TimeoutClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        def post(self, *args, **kwargs):
            calls.append(True)
            raise TimeoutError("includes secrets that must not be echoed")

    monkeypatch.setattr(aiohttp, "ClientSession", lambda **kwargs: TimeoutClient())
    with pytest.raises(LoginError) as exc:
        asyncio.run(exchange_code(configuration(), "C" * 43, "V" * 43))
    assert calls == [True] and exc.value.status == 503
    assert "includes secrets" not in str(exc.value)
