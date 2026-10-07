import asyncio
import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import psycopg
import pytest
from psycopg import sql
from psycopg.rows import dict_row
from redis import Redis

from app.account_login.config import LoginSettings, get_login_settings
from app.account_login.pkce_store import PkceStore
from app.account_login.protocol import (
    ATTEMPT_LIFETIME, SESSION_LIFETIME, LoginError, canonical_uuid4, digest,
    exchange_request, parse_json, pkce_challenge, session_is_active,
    validate_exchange_response,
)
from app.account_login.routes import get_login_service
from app.account_login.service import AccountLoginService
from app.account_login.store import LoginStore
from app.main import app


class MemoryRedis:
    def __init__(self):
        self.values, self.expirations = {}, {}

    def set(self, key, value, ex):
        self.values[key], self.expirations[key] = value, ex

    def getdel(self, key):
        self.expirations.pop(key, None)
        return self.values.pop(key, None)

    def delete(self, key):
        self.getdel(key)


@pytest.fixture
def settings() -> LoginSettings:
    return LoginSettings("http://localhost:5174", "http://localhost:5173/nagecen/security-login",
                         "http://host.docker.internal:8080/api/exchange_security_login_code.php",
                         "http://localhost:5173/nagecen/", "http://localhost:5174/auth/nagecen/callback",
                         "test-login-key", "synthetic-test-secret-" + "a" * 32)


@pytest.fixture
def login_environment(monkeypatch, settings):
    for key, value in {
        "APP_ENV": "development", "SECURITY_ACCOUNT_LOGIN_ENABLED": "true",
        "SECURITY_FRONTEND_URL": settings.frontend_origin,
        "NAGECEN_LOGIN_AUTHORIZE_URL": settings.authorization_url,
        "NAGECEN_LOGIN_EXCHANGE_URL": settings.exchange_url,
        "NAGECEN_ACCOUNT_ISSUER": settings.issuer,
        "SECURITY_TO_NAGECEN_LOGIN_KEY_ID": settings.key_id,
        "SECURITY_TO_NAGECEN_LOGIN_HMAC_SECRET": settings.secret, "COOKIE_SECURE": "false",
    }.items():
        monkeypatch.setenv(key, value)


def test_pkce_matches_rfc7636_example():
    assert pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_exact_bytes_and_separate_hmac_namespace(settings):
    now = datetime(2026, 10, 4, tzinfo=UTC)
    raw, headers, request_id = exchange_request("A" * 43, "B" * 43, settings.callback_url,
                                               settings.key_id, settings.secret, now)
    signed = b"nagecen-security-login-v1." + headers["X-Security-Login-Timestamp"].encode() + b"." + raw
    assert headers["X-Security-Login-Signature"] == "sha256=" + hmac.new(settings.secret.encode(), signed, hashlib.sha256).hexdigest()
    assert json.loads(raw)["request_id"] == request_id
    assert json.loads(raw)["redirect_uri"] == settings.callback_url
    assert raw != json.dumps(json.loads(raw), indent=2).encode()
    assert settings.secret not in repr(settings)


@pytest.mark.parametrize("raw", [b"[]", b"null", b"{} trailing", b'{"state":"a","state":"b"}', b"\xff", b" " * 8193])
def test_json_rejects_bad_bodies_without_echoing(raw):
    with pytest.raises(LoginError) as exc:
        parse_json(raw)
    assert exc.value.code == "invalid_request"
    assert str(exc.value) == "invalid_request"


@pytest.mark.parametrize("value", [42, "42", str(uuid.uuid1()), str(uuid.uuid4()).upper(), uuid.uuid4(), "not-a-uuid"])
def test_subject_is_canonical_uuid4(value):
    with pytest.raises(LoginError):
        canonical_uuid4(value)


def provider_response(settings, now):
    return {"status": "success", "version": "1", "request_id": str(uuid.uuid4()),
            "login_id": str(uuid.uuid4()), "issuer": settings.issuer, "audience": "nagecen-security",
            "subject": str(uuid.uuid4()), "issued_at": now.isoformat().replace("+00:00", "Z"),
            "validated_at": now.isoformat().replace("+00:00", "Z")}


@pytest.mark.parametrize("field,value", [("issuer", "https://wrong.example/"), ("audience", "wrong"),
                                        ("version", 1), ("status", "error"), ("subject", "42"),
                                        ("validated_at", "2026-10-04T00:00:00+00:00"),
                                        ("issued_at", "2020-01-01T00:00:00Z"), ("extra", "untrusted")])
def test_provider_response_is_strict(settings, field, value):
    now = datetime.now(UTC)
    values = provider_response(settings, now)
    values[field] = value
    with pytest.raises(LoginError) as exc:
        validate_exchange_response(json.dumps(values).encode(), values["request_id"], settings.issuer, now)
    assert exc.value.code == "login_unavailable"


def test_valid_provider_response(settings):
    now = datetime.now(UTC)
    values = provider_response(settings, now)
    assert validate_exchange_response(json.dumps(values).encode(), values["request_id"], settings.issuer, now) == (uuid.UUID(values["subject"]), uuid.UUID(values["login_id"]))
    with pytest.raises(LoginError):
        validate_exchange_response(json.dumps(values).encode(), str(uuid.uuid4()), settings.issuer, now)


@pytest.mark.parametrize("change", ["expired", "idle", "revoked", "disabled", "future"])
def test_session_expiration_enforced_on_server(change):
    now = datetime.now(UTC)
    row = {"created_at": now - timedelta(minutes=30), "last_seen_at": now,
           "expires_at": now + timedelta(hours=7), "revoked_at": None, "disabled_at": None}
    assert session_is_active(row, now)
    if change == "expired": row["expires_at"] = now
    if change == "idle": row["last_seen_at"] = now - timedelta(hours=1)
    if change == "revoked": row["revoked_at"] = now
    if change == "disabled": row["disabled_at"] = now
    if change == "future": row["last_seen_at"] = now + timedelta(seconds=1)
    assert not session_is_active(row, now)


def test_pkce_is_ephemeral_and_single_use():
    redis = MemoryRedis()
    store, attempt_id = PkceStore(redis), uuid.uuid4()
    store.put(attempt_id, "A" * 43)
    assert redis.expirations[store.key(attempt_id)] == 600
    assert store.take(attempt_id) == "A" * 43
    assert store.take(attempt_id) is None


def test_real_redis_pkce_is_nonpersistent_and_single_use():
    url = os.getenv("ACCOUNT_LOGIN_TEST_REDIS_URL")
    if not url:
        pytest.skip("専用のACCOUNT_LOGIN_TEST_REDIS_URLが必要です")
    client = Redis.from_url(url, decode_responses=True)
    store, attempt_id = PkceStore(client), uuid.uuid4()
    key = store.key(attempt_id)
    try:
        store.put(attempt_id, "A" * 43)
        assert 0 < client.ttl(key) <= 600
        assert store.take(attempt_id) == "A" * 43
        assert store.take(attempt_id) is None
        store.put(attempt_id, "B" * 43)
        store.delete(attempt_id)
        assert not client.exists(key)
        assert client.config_get("appendonly")["appendonly"] == "no"
        assert client.config_get("save")["save"] == ""
    finally:
        client.delete(key)


def test_configuration_is_off_by_default(monkeypatch):
    monkeypatch.delenv("SECURITY_ACCOUNT_LOGIN_ENABLED", raising=False)
    with pytest.raises(LoginError):
        get_login_settings()


def test_local_configuration(login_environment, settings):
    assert get_login_settings() == settings


@pytest.mark.parametrize("key,value", [
    ("APP_ENV", "production"), ("APP_ENV", "staging"),
    ("SECURITY_TO_NAGECEN_LOGIN_HMAC_SECRET", "short"),
    ("SECURITY_TO_NAGECEN_LOGIN_HMAC_SECRET", "replace_with" + "a" * 40),
    ("SECURITY_TO_NAGECEN_LOGIN_KEY_ID", "bad\nkey"),
    ("NAGECEN_LOGIN_AUTHORIZE_URL", "http://localhost:5173/path?return_url=https://evil.example"),
    ("NAGECEN_LOGIN_EXCHANGE_URL", "http://private.example/api"),
    ("NAGECEN_LOGIN_EXCHANGE_URL", "https://other.example/api"),
    ("NAGECEN_LOGIN_EXCHANGE_URL", "http://user:password@localhost:5173/api"),
    ("NAGECEN_LOGIN_EXCHANGE_URL", "http://@localhost:5173/api"),
    ("NAGECEN_LOGIN_EXCHANGE_URL", "http://localhost:5173/api\n"),
    ("NAGECEN_ACCOUNT_ISSUER", "http://localhost:5173/nagecen"),
    ("SECURITY_FRONTEND_URL", "http://localhost:5174/another-path"),
])
def test_incomplete_or_unsafe_configuration_is_rejected(login_environment, monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(LoginError):
        get_login_settings()


def test_existing_handoff_secret_cannot_be_reused(login_environment, monkeypatch, settings):
    monkeypatch.setenv("NAGECEN_TO_SECURITY_HMAC_SECRET", settings.secret)
    with pytest.raises(LoginError):
        get_login_settings()


@pytest.fixture
def db():
    # Never fall back to the application's DATABASE_URL or mutate its real DB.
    dsn = os.getenv("ACCOUNT_LOGIN_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("専用のACCOUNT_LOGIN_TEST_DATABASE_URLが必要です")
    schema = "account_login_test_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        root = Path(__file__).resolve().parents[2]
        migration = (root / "database/20261004_add_security_account_login.sql").read_text()
        connection.execute(migration)
        try:
            yield connection, dsn, schema
        finally:
            connection.execute("SET search_path TO public")
            # Only this fixture's newly-created, UUID-named test schema.
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


@pytest.fixture
def login(db, settings, monkeypatch):
    service = AccountLoginService(settings, LoginStore(db[0]), PkceStore(MemoryRedis()))
    subject = uuid.uuid4()
    calls = []

    async def fake_exchange(configuration, code, verifier):
        calls.append((code, verifier))
        return subject, uuid.uuid4()

    monkeypatch.setattr("app.account_login.service.exchange_code", fake_exchange)
    return service, subject, calls


def begin(service, now=None, previous=None):
    url, browser = service.start(previous, "127.0.0.1", now or datetime.now(UTC))
    return parse_qs(urlsplit(url).query)["state"][0], browser


def complete(service, state, browser, previous=None):
    return asyncio.run(service.complete({"state": state, "code": "C" * 43}, browser, previous))


def test_real_db_complete_keeps_only_hashes_and_stable_identity(login, db):
    service, subject, calls = login
    state, browser = begin(service)
    assert calls == []
    with db[0].cursor() as cursor:
        cursor.execute("SELECT * FROM security_login_attempts")
        attempt = cursor.fetchone()
        assert attempt["state_hash"] == digest(state)
        assert attempt["browser_token_hash"] == digest(browser)
        assert state not in repr(attempt) and browser not in repr(attempt)
        assert "pkce_verifier" not in attempt
    result, token = complete(service, state, browser)
    assert result == {"status": "success", "redirect_path": "/check"}
    assert len(calls) == 1 and service.pkce.client.values == {}
    session = service.session(token, datetime.now(UTC))
    account_id = session["account_id"]
    assert session["token_hash"] == digest(token) and token not in repr(session)
    state2, browser2 = begin(service)
    _, token2 = complete(service, state2, browser2, token)
    assert token2 != token
    assert service.session(token, datetime.now(UTC)) is None
    assert service.session(token2, datetime.now(UTC))["account_id"] == account_id
    assert db[0].execute("SELECT subject FROM security_accounts").fetchone()["subject"] == subject


@pytest.mark.parametrize("case", ["missing_cookie", "wrong_cookie", "wrong_state", "extra", "bad_code"])
def test_invalid_completion_never_exchanges(login, case):
    service, _, calls = login
    state, browser = begin(service)
    values = {"state": state, "code": "C" * 43}
    if case == "missing_cookie": browser = None
    if case == "wrong_cookie": browser = "X" * 43
    if case == "wrong_state": values["state"] = "Z" * 43
    if case == "extra": values["subject"] = str(uuid.uuid4())
    if case == "bad_code": values["code"] = "secret-that-must-not-be-echoed"
    with pytest.raises(LoginError):
        asyncio.run(service.complete(values, browser, None))
    assert calls == []


def test_expired_or_evicted_pkce_fails_closed(login):
    service, _, calls = login
    state, browser = begin(service, datetime.now(UTC) - ATTEMPT_LIFETIME)
    with pytest.raises(LoginError) as exc:
        complete(service, state, browser)
    assert exc.value.status == 410
    state, browser = begin(service)
    service.pkce.client.values.clear()
    with pytest.raises(LoginError) as exc:
        complete(service, state, browser)
    assert exc.value.status == 410 and calls == []


def test_pkce_mismatch_fails_before_code_exchange(login):
    service, _, calls = login
    state, browser = begin(service)
    attempt_id = next(iter(service.pkce.client.values))
    service.pkce.client.values[attempt_id] = "X" * 43
    with pytest.raises(LoginError) as exc:
        complete(service, state, browser)
    assert exc.value.status == 410
    assert calls == []


def test_replay_and_cancel_do_not_authenticate(login):
    service, _, calls = login
    state, browser = begin(service)
    result, token = asyncio.run(service.complete({"state": state, "error": "access_denied"}, browser, None))
    assert result["status"] == "cancelled" and token is None and calls == []
    state, browser = begin(service)
    complete(service, state, browser)
    with pytest.raises(LoginError) as exc:
        complete(service, state, browser)
    assert exc.value.status == 409 and len(calls) == 1


def test_restart_invalidates_previous_browser_attempt(login):
    service, _, calls = login
    state, browser = begin(service)
    state2, browser2 = begin(service, previous=browser)
    with pytest.raises(LoginError):
        complete(service, state, browser)
    complete(service, state2, browser2)
    assert len(calls) == 1


def test_remote_failure_consumes_attempt_without_creating_session(login, db, monkeypatch):
    service, _, _ = login
    state, browser = begin(service)

    async def failing_exchange(*args):
        raise LoginError(503, "login_unavailable", "再試行してください")

    monkeypatch.setattr("app.account_login.service.exchange_code", failing_exchange)
    with pytest.raises(LoginError):
        complete(service, state, browser)
    row = db[0].execute("SELECT status FROM security_login_attempts").fetchone()
    assert row["status"] == "failed"
    assert db[0].execute("SELECT count(*) AS total FROM security_account_sessions").fetchone()["total"] == 0
    with pytest.raises(LoginError) as exc:
        complete(service, state, browser)
    assert exc.value.status == 409


def test_logout_revokes_session_and_pending_attempt(login):
    service, _, calls = login
    state, browser = begin(service)
    _, token = complete(service, state, browser)
    pending_state, pending_browser = begin(service)
    service.logout(token, pending_browser, datetime.now(UTC))
    assert service.session(token, datetime.now(UTC)) is None
    with pytest.raises(LoginError):
        complete(service, pending_state, pending_browser)
    assert len(calls) == 1
    service.logout(token, pending_browser, datetime.now(UTC))


def test_logout_during_exchange_cannot_create_session(login, db, monkeypatch):
    service, subject, _ = login
    state, browser = begin(service)

    async def concurrent_logout(*args):
        service.logout(None, browser, datetime.now(UTC))
        return subject, uuid.uuid4()

    monkeypatch.setattr("app.account_login.service.exchange_code", concurrent_logout)
    with pytest.raises(LoginError):
        complete(service, state, browser)
    assert db[0].execute("SELECT count(*) AS total FROM security_account_sessions").fetchone()["total"] == 0


def test_local_disabled_account_cannot_login(login, db):
    service, _, _ = login
    state, browser = begin(service)
    _, token = complete(service, state, browser)
    db[0].execute("UPDATE security_accounts SET disabled_at = %s", (datetime.now(UTC),))
    assert service.session(token, datetime.now(UTC)) is None
    state, browser = begin(service)
    with pytest.raises(LoginError) as exc:
        complete(service, state, browser)
    assert exc.value.code == "account_disabled"


def test_real_db_idle_and_absolute_limits_do_not_refresh_on_poll(login):
    service, _, _ = login
    state, browser = begin(service)
    _, token = complete(service, state, browser)
    session = service.session(token, datetime.now(UTC))
    first_seen = session["last_seen_at"]
    assert service.session(token, first_seen + timedelta(minutes=59))["last_seen_at"] == first_seen
    assert service.session(token, first_seen + timedelta(hours=1)) is None
    assert service.session(token, first_seen + timedelta(minutes=59), touch=True) is not None
    for minute in range(90, 480, 30):
        assert service.session(token, first_seen + timedelta(minutes=minute), touch=True)
    assert service.session(token, session["expires_at"], touch=True) is None


def test_real_db_single_use_under_concurrent_claims(login, db):
    service, _, _ = login
    state, browser = begin(service)

    def claim():
        with psycopg.connect(db[1], autocommit=True, row_factory=dict_row) as conn:
            conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(db[2])))
            try:
                LoginStore(conn).claim_attempt(digest(state), digest(browser), datetime.now(UTC))
                return "claimed"
            except LoginError as exc:
                return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: claim(), range(2)))
    assert sorted(results) == ["claimed", "login_already_used"]


def test_rate_limit_does_not_store_plain_ip(login, db):
    service, _, _ = login
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    for _ in range(20):
        begin(service, now)
    with pytest.raises(LoginError) as exc:
        begin(service, now)
    assert exc.value.status == 429
    assert "127.0.0.1" not in repr(db[0].execute("SELECT * FROM security_login_rate_limits").fetchall())


def test_identity_is_scoped_to_issuer_and_other_devices_survive(login, db):
    service, _, _ = login
    state, browser = begin(service)
    _, token = complete(service, state, browser)
    account_id = service.session(token, datetime.now(UTC))["account_id"]
    state, browser = begin(service)
    _, second_device_token = complete(service, state, browser)
    assert service.session(token, datetime.now(UTC))["account_id"] == account_id
    assert service.session(second_device_token, datetime.now(UTC))["account_id"] == account_id
    service.settings = dataclasses.replace(service.settings, issuer="https://separate-test-issuer.example/")
    assert service.session(token, datetime.now(UTC)) is None
    state, browser = begin(service)
    _, other_issuer_token = complete(service, state, browser)
    assert service.session(other_issuer_token, datetime.now(UTC))["account_id"] != account_id
    assert db[0].execute("SELECT count(*) AS total FROM security_accounts").fetchone()["total"] == 2


def test_migration_is_additive_and_reentrant(db):
    root = Path(__file__).resolve().parents[2]
    db[0].execute("CREATE TABLE existing_test_data (value TEXT)")
    db[0].execute("INSERT INTO existing_test_data VALUES ('keep-me')")
    db[0].execute((root / "database/schema.sql").read_text())
    db[0].execute((root / "database/20261004_add_security_account_login.sql").read_text())
    assert db[0].execute("SELECT value FROM existing_test_data").fetchone()["value"] == "keep-me"
    for name in ("scan_jobs", "nagecen_handoffs", "security_accounts", "security_account_sessions"):
        assert db[0].execute("SELECT to_regclass(%s) AS table_name", (name,)).fetchone()["table_name"] is not None


async def asgi_call(path, method="POST", payload=None, origin="http://localhost:5174", cookie="", raw=None, content_type="application/json"):
    headers = [(b"content-type", content_type.encode())]
    if origin is not None: headers.append((b"origin", origin.encode()))
    if cookie: headers.append((b"cookie", cookie.encode()))
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
             "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"", "headers": headers,
             "server": ("localhost", 8000), "client": ("127.0.0.1", 55000), "root_path": ""}
    body = raw if raw is not None else json.dumps(payload if payload is not None else {}).encode()
    messages = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message): messages.append(message)
    await app(scope, receive, send)
    start = next(m for m in messages if m["type"] == "http.response.start")
    response_headers = [(k.decode(), v.decode()) for k, v in start["headers"]]
    response_body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return start["status"], response_headers, json.loads(response_body)


@pytest.fixture
def api(login):
    previous = app.dependency_overrides.copy()
    app.dependency_overrides[get_login_service] = lambda: login[0]
    try:
        yield lambda *args, **kwargs: asyncio.run(asgi_call(*args, **kwargs))
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


def cookie_from(headers, name):
    for key, value in headers:
        if key == "set-cookie":
            jar = SimpleCookie(value)
            if name in jar: return jar[name]
    raise AssertionError("cookie not set")


def test_api_complete_session_and_logout(api, login):
    service = login[0]
    status, headers, body = api("/api/auth/nagecen/start")
    assert status == 200
    assert dict(headers)["cache-control"] == "no-store"
    start = cookie_from(headers, service.settings.start_cookie)
    assert start["httponly"] and start["samesite"] == "lax" and start["path"] == "/" and not start["domain"]
    state = parse_qs(urlsplit(body["authorization_url"]).query)["state"][0]
    status, headers, body = api("/api/auth/nagecen/complete", payload={"state": state, "code": "C" * 43},
                              cookie=f"{service.settings.start_cookie}={start.value}")
    assert status == 200 and body["redirect_path"] == "/check"
    session = cookie_from(headers, service.settings.session_cookie)
    assert int(session["max-age"]) == 8 * 3600
    cookie = f"{service.settings.session_cookie}={session.value}"
    status, _, body = api("/api/auth/session", method="GET", cookie=cookie)
    assert status == 200 and body["authenticated"]
    assert session.value not in json.dumps(body) and "subject" not in body
    status, _, body = api("/api/auth/logout", cookie=cookie)
    assert status == 200 and not body["authenticated"]
    assert api("/api/auth/session", method="GET", cookie=cookie)[2] == {"authenticated": False}


def test_legacy_handoff_cookie_is_not_account_authentication(api, login):
    service = login[0]
    state, browser = begin(service)
    _, token = complete(service, state, browser)
    assert api("/api/auth/session", method="GET", cookie=f"nagecen_security_handoff_session={token}")[2] == {"authenticated": False}


def test_api_session_cookie_is_host_only_secure_when_requested(api, login):
    service = login[0]
    service.settings = dataclasses.replace(service.settings, cookie_secure=True)
    status, headers, body = api("/api/auth/nagecen/start")
    assert status == 200
    cookie = cookie_from(headers, "__Host-nagecen_security_account_start")
    assert cookie["secure"] and cookie["httponly"] and cookie["path"] == "/" and not cookie["domain"]


@pytest.mark.parametrize("origin", [None, "null", "https://evil.example", "http://localhost:5173", "http://localhost:5174.evil.example"])
def test_api_post_rejects_foreign_origin(api, origin):
    status, headers, body = api("/api/auth/nagecen/start", origin=origin)
    assert status == 403 and body["code"] == "csrf_failed"
    assert dict(headers)["referrer-policy"] == "no-referrer"


@pytest.mark.parametrize("raw,ctype", [(b"{}", "text/plain"), (b"[]", "application/json"),
                                      (b'{"subject":"untrusted"}', "application/json"),
                                      (b" " * 8193, "application/json")])
def test_api_post_rejects_bad_body_without_echoing(api, raw, ctype):
    status, _, body = api("/api/auth/nagecen/start", raw=raw, content_type=ctype)
    assert status == 400 and body["code"] == "invalid_request"
    assert "untrusted" not in json.dumps(body)


def test_off_flag_never_opens_database(monkeypatch):
    monkeypatch.delenv("SECURITY_ACCOUNT_LOGIN_ENABLED", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    status, headers, body = asyncio.run(asgi_call("/api/auth/nagecen/start"))
    assert status == 503 and body["code"] == "login_unavailable"
    assert dict(headers)["cache-control"] == "no-store"
