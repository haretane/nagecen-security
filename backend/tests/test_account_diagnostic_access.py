"""Real API/DB ownership checks; never use the application's DB or scan a site."""
import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
import pytest
from psycopg import sql
from psycopg.rows import dict_row
from redis.exceptions import RedisError

from app.account_login import access
from app.account_login.protocol import digest
from app.account_login.service import cookie_hash
from app.account_login.store import LoginStore
from app.api.routes import scan_jobs, site_verification, url_validation
from app.database import get_connection
from app.main import app
from app.security.auth_secret_store import create_authentication_secret_store
from app.security.safe_http_client import SafeHttpResponse
from app.security.url_validator import ValidatedUrl
from app.security.verification_meta import VERIFICATION_META_NAME
from test_account_login import asgi_call, db, login_environment, settings


@pytest.fixture(autouse=True)
def live_diagnostic_mode(monkeypatch):
    # These tests cover the retained live implementation, not submission mode.
    # Pause/rejection behavior is tested separately in test_diagnostic_availability.
    monkeypatch.setenv("SECURITY_DIAGNOSTICS_PAUSED", "false")


class SecretStore:
    def __init__(self):
        self.puts, self.deletes = [], []

    def put(self, job_id, secret):
        self.puts.append(job_id)

    def delete(self, job_id):
        self.deletes.append(job_id)


@pytest.fixture
def diagnostics(db, settings, login_environment, monkeypatch):
    connection, dsn, schema = db
    root = Path(__file__).resolve().parents[2]
    # Start with the pre-ownership schema to exercise an additive upgrade.
    connection.execute((root / "database/schema.sql").read_text().split("-- Apply after")[0])
    migration = (root / "database/20261004_add_diagnostic_account_ownership.sql").read_text()
    connection.execute(migration)
    accounts, cookies, tokens = [], [], []
    now = datetime.now(UTC)
    for label in ("A", "B"):
        account_id, token = uuid.uuid4(), label * 43
        connection.execute("""INSERT INTO security_accounts
            (id, issuer, subject, created_at, last_login_at) VALUES (%s, %s, %s, %s, %s)""",
            (account_id, settings.issuer, uuid.uuid4(), now, now))
        connection.execute("""INSERT INTO security_account_sessions
            (id, account_id, login_id, token_hash, created_at, expires_at, last_seen_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (uuid.uuid4(), account_id, uuid.uuid4(), digest(token), now - timedelta(hours=2), now + timedelta(hours=6), now))
        accounts.append(account_id)
        tokens.append(token)
        cookies.append(f"{settings.session_cookie}={token}")

    # Only the connection acquisition is substituted. Authentication uses the
    # real session query/issuer/expiry checks in the isolated test schema.
    def lookup(configuration, token, *, touch):
        token_hash = cookie_hash(token)
        if token_hash is None:
            return None
        return LoginStore(connection).session(token_hash, configuration.issuer, datetime.now(UTC), touch)

    monkeypatch.setattr(access, "lookup_session", lookup)
    effects = {"validation": [], "fetch": []}

    def validate(value):
        effects["validation"].append(value)
        parsed = urlsplit(value)
        return ValidatedUrl(value, parsed.scheme, parsed.hostname, 443, ("93.184.216.34",))

    async def fetch(value, **kwargs):
        effects["fetch"].append(value)
        row = connection.execute("SELECT token_hash FROM verification_challenges WHERE target_url = %s", (value,)).fetchone()
        token = known_tokens[row["token_hash"]]
        return SafeHttpResponse(value, 200, "text/html", f'<html><head><meta name="{VERIFICATION_META_NAME}" content="{token}"></head></html>'.encode(), 0)

    known_tokens = {}
    monkeypatch.setattr(site_verification, "validate_public_url", validate)
    monkeypatch.setattr(site_verification, "fetch_public_html", fetch)
    monkeypatch.setattr(scan_jobs, "validate_public_url", validate)
    monkeypatch.setattr(url_validation, "validate_public_url", validate)
    secret_store = SecretStore()

    def diagnostic_connection():
        # Real transaction semantics, separate from the autocommit login store.
        with psycopg.connect(dsn, row_factory=dict_row) as connection:
            connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
            yield connection

    previous = app.dependency_overrides.copy()
    app.dependency_overrides[get_connection] = diagnostic_connection
    app.dependency_overrides[create_authentication_secret_store] = lambda: secret_store

    def call(path, method="POST", payload=None, user=0, **kwargs):
        kwargs.setdefault("cookie", cookies[user] if user is not None else "")
        return asyncio.run(asgi_call(path, method=method, payload=payload, **kwargs))

    try:
        yield {"db": connection, "call": call, "accounts": accounts, "cookies": cookies,
               "tokens": tokens, "settings": settings, "known_tokens": known_tokens,
               "effects": effects, "secrets": secret_store, "migration": migration}
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


def create_target(context, user=0, **kwargs):
    url = "https://test-" + uuid.uuid4().hex + ".example/site/"
    status, _, challenge = context["call"]("/api/site-verifications", payload={"url": url}, user=user, **kwargs)
    assert status == 201, challenge
    context["known_tokens"][digest(challenge["token"])] = challenge["token"]
    status, _, target = context["call"](f'/api/site-verifications/{challenge["verification_id"]}/confirm',
                                       payload={"token": challenge["token"]}, user=user)
    assert status == 200, target
    return challenge, target


def scan_input(target_id):
    return {"verified_target_id": str(target_id), "level_id": "basic",
            "authorization_confirmed": True, "active_scan_confirmed": False,
            "data_change_risk_acknowledged": False, "authentication_type": "none",
            "service_features": ["view_only"]}


def create_job(context, user=0):
    challenge, target = create_target(context, user=user)
    status, headers, job = context["call"]("/api/scan-jobs", payload=scan_input(target["verified_target_id"]), user=user)
    assert status == 201, job
    assert dict(headers)["cache-control"] == "no-store"
    return challenge, target, job


PROTECTED = [
    ("/api/url-validation", "POST"), ("/api/site-verifications", "POST"),
    (f"/api/site-verifications/{uuid.uuid4()}/confirm", "POST"),
    ("/api/scan-jobs", "POST"), ("/api/scan-jobs/levels", "GET"),
    (f"/api/scan-jobs/{uuid.uuid4()}", "GET"),
    (f"/api/scan-jobs/{uuid.uuid4()}/cancel", "POST"),
]


@pytest.mark.parametrize("path,method", PROTECTED)
@pytest.mark.parametrize("cookie", ["", "nagecen_security_handoff_session=" + "C" * 43,
                                   "nagecen_security_account_session_dev=invalid"])
def test_guard_before_parsing_dependencies_or_outbound_work(settings, login_environment, monkeypatch, path, method, cookie):
    monkeypatch.setattr(access, "lookup_session", lambda *args, **kwargs: None)

    def unexpected(*args, **kwargs):
        raise AssertionError("Unauthenticated requests must not reach the diagnostic dependencies")

    previous = app.dependency_overrides.copy()
    app.dependency_overrides[get_connection] = unexpected
    app.dependency_overrides[create_authentication_secret_store] = unexpected
    monkeypatch.setattr(url_validation, "validate_public_url", unexpected)
    try:
        status, headers, body = asyncio.run(asgi_call(path, method, cookie=cookie, raw=b'{"password":"secret-echo"'))
        assert status == 401 and body["code"] == "login_required"
        assert "secret-echo" not in json.dumps(body)
        assert dict(headers)["cache-control"] == "no-store"
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


def test_default_off_keeps_existing_url_api(monkeypatch):
    monkeypatch.delenv("SECURITY_ACCOUNT_LOGIN_ENABLED", raising=False)
    monkeypatch.setattr(access, "authenticate", lambda *_: pytest.fail("Legacy mode must not access login DB"))
    monkeypatch.setattr(url_validation, "validate_public_url", lambda value: ValidatedUrl(value, "https", "test.example", 443, ("93.184.216.34",)))
    status, _, body = asyncio.run(asgi_call("/api/url-validation", payload={"url": "https://test.example/"}, origin=None))
    assert status == 200 and body["valid"] is True


def test_guard_fails_closed_in_production(login_environment, monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setattr(access, "lookup_session", lambda *args, **kwargs: pytest.fail("No DB call in production"))
    status, _, body = asyncio.run(asgi_call("/api/scan-jobs/levels", "GET"))
    assert status == 503 and body["code"] == "login_unavailable"


@pytest.mark.parametrize("error_type", [psycopg.OperationalError, RedisError, KeyError])
def test_guard_infrastructure_errors_do_not_echo_secret_details(login_environment, monkeypatch, error_type):
    def fail(*args, **kwargs):
        raise error_type("private-connection-or-secret-value")

    monkeypatch.setattr(access, "lookup_session", fail)
    status, _, body = asyncio.run(asgi_call("/api/scan-jobs/levels", "GET"))
    assert status == 503 and body["code"] == "diagnostic_unavailable"
    assert "private-connection-or-secret-value" not in json.dumps(body)


def test_owned_chain_and_worker_updates(diagnostics):
    context = diagnostics
    challenge, target, job = create_job(context)
    for table, record_id in (("verification_challenges", challenge["verification_id"]),
                             ("verified_targets", target["verified_target_id"]), ("scan_jobs", job["id"])):
        row = context["db"].execute(sql.SQL("SELECT * FROM {} WHERE id = %s").format(sql.Identifier(table)), (record_id,)).fetchone()
        assert row["account_id"] == context["accounts"][0]
        assert row["nagecen_handoff_id"] is None
    # Worker is a trusted backend actor; updating progress must remain possible.
    context["db"].execute("UPDATE scan_jobs SET status = 'completed', completed_check_ids = '[\"passive_scan\"]' WHERE id = %s", (job["id"],))
    status, _, result = context["call"](f'/api/scan-jobs/{job["id"]}', "GET")
    assert status == 200 and result["status"] == "completed"
    assert result["checked_items"] and result["overall_ai_prompt"]
    assert "account_id" not in result


def test_other_account_cannot_confirm_start_read_or_cancel(diagnostics):
    context = diagnostics
    challenge, target, job = create_job(context)
    before = context["db"].execute("SELECT confirmation_attempt_count FROM verification_challenges WHERE id = %s", (challenge["verification_id"],)).fetchone()
    context["effects"]["fetch"].clear()
    status, _, body = context["call"](f'/api/site-verifications/{challenge["verification_id"]}/confirm',
                                      payload={"token": challenge["token"]}, user=1)
    assert status == 404 and body["detail"]["code"] == "not_found"
    assert context["effects"]["fetch"] == []
    assert context["db"].execute("SELECT confirmation_attempt_count FROM verification_challenges WHERE id = %s", (challenge["verification_id"],)).fetchone() == before
    assert context["call"]("/api/scan-jobs", payload=scan_input(target["verified_target_id"]), user=1)[0] == 422
    for suffix, method in (("", "GET"), ("/cancel", "POST")):
        denied = context["call"](f'/api/scan-jobs/{job["id"]}{suffix}', method, user=1)
        absent = context["call"](f'/api/scan-jobs/{uuid.uuid4()}{suffix}', method, user=1)
        assert denied[0] == absent[0] == 404 and denied[2] == absent[2]
        assert job["target_url"] not in json.dumps(denied[2])
    assert context["secrets"].deletes == []
    assert context["db"].execute("SELECT status FROM scan_jobs WHERE id = %s", (job["id"],)).fetchone()["status"] == "queued"
    assert context["db"].execute("SELECT COUNT(*) AS count FROM nagecen_webhook_outbox").fetchone()["count"] == 0
    status, _, result = context["call"](f'/api/scan-jobs/{job["id"]}/cancel')
    assert status == 200 and result["status"] == "cancelled"
    assert context["secrets"].deletes == [uuid.UUID(job["id"])]


@pytest.mark.parametrize("origin", [None, "null", "http://localhost:5173", "http://localhost:5174.evil.example"])
def test_csrf_blocks_changes_even_with_a_valid_cookie(diagnostics, origin):
    context = diagnostics
    _, _, job = create_job(context)
    for path, payload in (("/api/url-validation", {"url": "https://test.example/"}),
                          ("/api/site-verifications", {"url": "https://test.example/"}),
                          (f'/api/scan-jobs/{job["id"]}/cancel', {})):
        assert context["call"](path, payload=payload, origin=origin)[0] == 403
    assert context["secrets"].deletes == []


@pytest.mark.parametrize("case", ["expired", "idle", "revoked", "disabled", "wrong_issuer"])
def test_session_state_is_enforced_for_results_and_cancellation(diagnostics, case):
    context = diagnostics
    _, _, job = create_job(context)
    if case == "expired":
        context["db"].execute("UPDATE security_account_sessions SET created_at = now() - interval '9 hours', expires_at = now() - interval '1 hour' WHERE token_hash = %s", (digest(context["tokens"][0]),))
    elif case == "idle":
        context["db"].execute("UPDATE security_account_sessions SET last_seen_at = now() - interval '1 hour' WHERE token_hash = %s", (digest(context["tokens"][0]),))
    elif case == "revoked":
        context["db"].execute("UPDATE security_account_sessions SET revoked_at = now() WHERE token_hash = %s", (digest(context["tokens"][0]),))
    elif case == "disabled":
        context["db"].execute("UPDATE security_accounts SET disabled_at = now() WHERE id = %s", (context["accounts"][0],))
    else:
        context["db"].execute("UPDATE security_accounts SET issuer = 'https://other.example/' WHERE id = %s", (context["accounts"][0],))
    assert context["call"](f'/api/scan-jobs/{job["id"]}', "GET")[0] == 401
    assert context["call"](f'/api/scan-jobs/{job["id"]}/cancel')[0] == 401
    assert context["secrets"].deletes == []


def test_get_polling_does_not_extend_idle_limit_but_user_posts_do(diagnostics):
    context = diagnostics
    _, _, job = create_job(context)
    context["db"].execute("UPDATE security_account_sessions SET last_seen_at = now() - interval '30 minutes' WHERE token_hash = %s", (digest(context["tokens"][0]),))
    before = context["db"].execute("SELECT last_seen_at FROM security_account_sessions WHERE token_hash = %s", (digest(context["tokens"][0]),)).fetchone()
    assert context["call"](f'/api/scan-jobs/{job["id"]}', "GET", origin=None)[0] == 200
    assert context["db"].execute("SELECT last_seen_at FROM security_account_sessions WHERE token_hash = %s", (digest(context["tokens"][0]),)).fetchone() == before
    assert context["call"]("/api/url-validation", payload={"url": "https://test.example/"})[0] == 200
    after = context["db"].execute("SELECT last_seen_at FROM security_account_sessions WHERE token_hash = %s", (digest(context["tokens"][0]),)).fetchone()
    assert after["last_seen_at"] > before["last_seen_at"]


@pytest.mark.parametrize("raw,content_type,expected", [
    (b'{"url":"a","url":"b"}', "application/json", 400),
    (b'{"secret":"do-not-echo"}', "text/plain", 400),
    (b'{"secret":"do-not-echo"}', "application/json", 422),
    (b'"do-not-echo"', "application/json", 400),
    (b'{"secret":"do-not-echo"}' + b" " * 8192, "application/json", 400),
])
def test_bad_json_or_model_validation_does_not_echo_inputs(diagnostics, raw, content_type, expected):
    status, _, body = diagnostics["call"]("/api/site-verifications", raw=raw, content_type=content_type)
    assert status == expected and "do-not-echo" not in json.dumps(body)


def test_form_password_is_not_echoed_on_invalid_request(diagnostics):
    _, target = create_target(diagnostics)
    payload = scan_input(target["verified_target_id"])
    payload.update(authentication_type="form", form_authentication={"login_url": target["final_url"],
                   "identifier": "test-user", "password": "never-echo-password"}, level_id={"bad": "shape"})
    status, _, body = diagnostics["call"]("/api/scan-jobs", payload=payload)
    assert status == 422 and "never-echo-password" not in json.dumps(body)
    assert diagnostics["secrets"].puts == []


def test_owner_injection_and_stale_handoff_cannot_reassign_new_challenge(diagnostics):
    context = diagnostics
    status, _, response = context["call"]("/api/site-verifications", payload={"url": "https://test.example/",
        "account_id": str(context["accounts"][1]), "nagecen_handoff_id": str(uuid.uuid4())},
        cookie=context["cookies"][0] + "; nagecen_security_handoff_session=stale-handoff")
    assert status == 201
    row = context["db"].execute("SELECT account_id, nagecen_handoff_id FROM verification_challenges WHERE id = %s", (response["verification_id"],)).fetchone()
    assert row == {"account_id": context["accounts"][0], "nagecen_handoff_id": None}


def test_legacy_records_not_adopted_and_feature_off_does_not_expose_owned_records(diagnostics, monkeypatch):
    context = diagnostics
    owned_challenge, owned_target, owned_job = create_job(context)
    monkeypatch.setenv("SECURITY_ACCOUNT_LOGIN_ENABLED", "false")
    old_challenge, old_target, old_job = create_job(context, user=None)
    assert context["call"](f'/api/scan-jobs/{owned_job["id"]}', "GET", user=None)[0] == 404
    assert context["call"](f'/api/scan-jobs/{owned_job["id"]}/cancel', user=None)[0] == 404
    assert context["call"](f'/api/site-verifications/{owned_challenge["verification_id"]}/confirm',
        payload={"token": owned_challenge["token"]}, user=None)[0] == 404
    assert context["call"]("/api/scan-jobs", payload=scan_input(owned_target["verified_target_id"]), user=None)[0] == 422
    assert context["call"](f'/api/scan-jobs/{old_job["id"]}', "GET", user=None)[0] == 200
    monkeypatch.setenv("SECURITY_ACCOUNT_LOGIN_ENABLED", "true")
    assert context["call"](f'/api/scan-jobs/{old_job["id"]}', "GET")[0] == 404
    assert context["call"](f'/api/scan-jobs/{old_job["id"]}/cancel')[0] == 404
    assert context["call"]("/api/scan-jobs", payload=scan_input(old_target["verified_target_id"]))[0] == 422
    assert context["call"](f'/api/site-verifications/{old_challenge["verification_id"]}/confirm', payload={"token": old_challenge["token"]})[0] == 404
    for table in ("verification_challenges", "verified_targets", "scan_jobs"):
        assert context["db"].execute(sql.SQL("SELECT count(*) AS count FROM {} WHERE account_id IS NULL").format(sql.Identifier(table))).fetchone()["count"] == 1


def test_legacy_mode_works_before_ownership_migration(diagnostics, monkeypatch):
    context = diagnostics
    monkeypatch.setenv("SECURITY_ACCOUNT_LOGIN_ENABLED", "false")
    for table in ("scan_jobs", "verified_targets", "verification_challenges"):
        context["db"].execute(sql.SQL("ALTER TABLE {} DROP COLUMN account_id").format(sql.Identifier(table)))
    # Remove only our test schema's ownership triggers to represent an old DB.
    context["db"].execute("DROP FUNCTION security_assert_diagnostic_owner() CASCADE")
    _, _, job = create_job(context, user=None)
    assert context["call"](f'/api/scan-jobs/{job["id"]}', "GET", user=None)[0] == 200
    assert context["call"](f'/api/scan-jobs/{job["id"]}/cancel', user=None)[0] == 200
    monkeypatch.setenv("SECURITY_ACCOUNT_LOGIN_ENABLED", "true")
    status, _, response = context["call"](f'/api/scan-jobs/{job["id"]}', "GET")
    assert status == 503 and response["code"] == "diagnostic_unavailable"


def test_migration_is_reentrant_and_db_rejects_cross_account_or_reassignment(diagnostics):
    context = diagnostics
    _, target, job = create_job(context)
    context["db"].execute(context["migration"])
    for statement, args in (
        ("UPDATE verification_challenges SET account_id = %s WHERE id = (SELECT verification_challenge_id FROM verified_targets WHERE id = %s)", (context["accounts"][1], target["verified_target_id"])),
        ("UPDATE verified_targets SET account_id = %s WHERE id = %s", (context["accounts"][1], target["verified_target_id"])),
        ("UPDATE scan_jobs SET account_id = %s WHERE id = %s", (context["accounts"][1], job["id"])),
        ("UPDATE scan_jobs SET account_id = NULL WHERE id = %s", (job["id"],)),
    ):
        with pytest.raises(psycopg.errors.CheckViolation):
            context["db"].execute(statement, args)
    _, target_b = create_target(context, user=1)
    with pytest.raises(psycopg.errors.CheckViolation):
        context["db"].execute("UPDATE scan_jobs SET verified_target_id = %s WHERE id = %s", (target_b["verified_target_id"], job["id"]))
    assert context["db"].execute("SELECT account_id FROM scan_jobs WHERE id = %s", (job["id"],)).fetchone()["account_id"] == context["accounts"][0]


def test_queue_cap_remains_global_across_accounts(diagnostics):
    context = diagnostics
    _, target_a = create_target(context)
    _, target_b = create_target(context, user=1)
    for i in range(scan_jobs.MAX_PENDING_SCAN_JOBS):
        target = (target_a, target_b)[i % 2]
        assert context["call"]("/api/scan-jobs", payload=scan_input(target["verified_target_id"]), user=i % 2)[0] == 201
    assert context["call"]("/api/scan-jobs", payload=scan_input(target_b["verified_target_id"]), user=1)[0] == 429


@pytest.mark.parametrize("status", ["running", "completed", "failed", "cancelled"])
def test_owner_cancellation_preserves_existing_status_rules(diagnostics, status):
    context = diagnostics
    _, _, job = create_job(context)
    context["db"].execute("UPDATE scan_jobs SET status = %s WHERE id = %s", (status, job["id"]))
    code, _, body = context["call"](f'/api/scan-jobs/{job["id"]}/cancel')
    assert code == 409
    assert body["detail"]["code"] == ("scan_already_running" if status == "running" else "scan_not_cancellable")
    assert context["secrets"].deletes == []


def test_form_secret_created_only_for_owned_target(diagnostics):
    context = diagnostics
    _, target = create_target(context)
    payload = scan_input(target["verified_target_id"])
    payload.update(authentication_type="form", form_authentication={
        "login_url": target["final_url"], "identifier": "test-user", "password": "temporary-test-password",
    })
    assert context["call"]("/api/scan-jobs", payload=payload, user=1)[0] == 422
    assert context["secrets"].puts == []
    code, _, job = context["call"]("/api/scan-jobs", payload=payload)
    assert code == 201 and context["secrets"].puts == [uuid.UUID(job["id"])]
    assert "temporary-test-password" not in json.dumps(job)
    assert context["call"](f'/api/scan-jobs/{job["id"]}/cancel')[0] == 200
    assert context["secrets"].deletes == [uuid.UUID(job["id"])]


def test_sql_ownership_guard_also_rejects_null_parent_and_foreign_accounts(diagnostics):
    context = diagnostics
    challenge, target, job = create_job(context)
    source = context["db"].execute("SELECT * FROM scan_jobs WHERE id = %s", (job["id"],)).fetchone()
    # Copy all fields into a new job, but forge the owner or erase it.
    for owner in (None, context["accounts"][1]):
        with pytest.raises(psycopg.errors.CheckViolation):
            context["db"].execute("""INSERT INTO scan_jobs
                (id, verified_target_id, level_id, status, target_url, target_host,
                 target_origin, target_base_path, consent_confirmed_at, created_at, account_id)
                VALUES (%s, %s, %s, 'queued', %s, %s, %s, %s, %s, %s, %s)""",
                (uuid.uuid4(), target["verified_target_id"], source["level_id"], source["target_url"],
                 source["target_host"], source["target_origin"], source["target_base_path"],
                 source["consent_confirmed_at"], source["created_at"], owner))
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        context["db"].execute("""INSERT INTO verification_challenges
            (id, target_url, target_host, token_hash, created_at, expires_at, account_id)
            VALUES (%s, 'https://test.example/', 'test.example', %s, now(), now() + interval '30 minutes', %s)""",
            (uuid.uuid4(), digest(uuid.uuid4().hex), uuid.uuid4()))
