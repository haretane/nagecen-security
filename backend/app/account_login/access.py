"""Conditional account protection for diagnostics, separate from product handoffs."""

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

import psycopg
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from psycopg.rows import dict_row
from redis.exceptions import RedisError
from starlette.concurrency import run_in_threadpool

from app.account_login.config import LoginSettings, get_login_settings
from app.account_login.protocol import MAX_BODY_BYTES, LoginError, parse_json
from app.account_login.routes import check_origin
from app.account_login.service import cookie_hash
from app.account_login.store import LoginStore


@dataclass(frozen=True)
class AccountContext:
    id: UUID


def account_login_enabled() -> bool:
    return os.getenv("SECURITY_ACCOUNT_LOGIN_ENABLED", "false").lower() == "true"


def lookup_session(settings: LoginSettings, token: str | None, *, touch: bool) -> dict | None:
    token_hash = cookie_hash(token)
    if token_hash is None:
        return None
    with psycopg.connect(os.environ["DATABASE_URL"], row_factory=dict_row,
                         autocommit=True, connect_timeout=3) as connection:
        return LoginStore(connection).session(token_hash, settings.issuer, datetime.now(UTC), touch=touch)


def authenticate(request: Request) -> AccountContext:
    settings = get_login_settings()  # Incomplete/production settings fail closed.
    check_origin(request, settings, optional=request.method in {"GET", "HEAD"})
    session = lookup_session(settings, request.cookies.get(settings.session_cookie),
                             touch=request.method not in {"GET", "HEAD"})
    if session is None:
        raise LoginError(401, "login_required", "NAGeCenアカウントでログインしてください。")
    return AccountContext(session["account_id"])


def get_account_context(request: Request) -> AccountContext | None:
    return getattr(request.state, "security_account", None)


def owner_filter(account: AccountContext | None) -> tuple[str, tuple]:
    # Only use the column when enabled: an unmigrated legacy DB must still work.
    return (" AND account_id = %s", (account.id,)) if account else ("", ())


def visible_record(row: dict | None, account: AccountContext | None) -> dict | None:
    if row is None:
        return None
    owner = row.get("account_id")
    # Disabling the feature must not expose records created in account mode.
    # SELECT * lets this work both before and after the additive migration.
    if account is None:
        return row if owner is None else None
    return row if owner == account.id else None


class AccountDiagnosticRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request: Request):
            enabled = account_login_enabled()
            request.state.security_account = None
            try:
                if enabled:
                    # Check login before parsing user data, resolving DB dependencies,
                    # validating a URL, fetching a site, or reading a scan result.
                    request.state.security_account = await run_in_threadpool(authenticate, request)
                    if request.method not in {"GET", "HEAD"}:
                        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
                            raise LoginError(400, "invalid_request", "JSON形式で送信してください。")
                        raw = bytearray()
                        async for chunk in request.stream():
                            if len(raw) + len(chunk) > MAX_BODY_BYTES:
                                raise LoginError(400, "invalid_request", "送信する情報が大きすぎます。")
                            raw.extend(chunk)
                        parse_json(bytes(raw))  # Reject malformed/duplicate-key JSON.
                        request._body = bytes(raw)  # Same bytes for FastAPI's models.
                response = await original(request)
            except LoginError as error:
                response = JSONResponse(status_code=error.status, content={
                    "status": "error", "code": error.code, "message": error.message,
                })
            except RequestValidationError:
                if not enabled:
                    raise
                # Pydantic's default input echo can expose form passwords or tokens.
                response = JSONResponse(status_code=422, content={"detail": {
                    "code": "invalid_request", "message": "入力内容を確認してください。",
                }})
            except (psycopg.Error, RedisError, KeyError):
                if not enabled:
                    raise
                response = JSONResponse(status_code=503, content={
                    "status": "error", "code": "diagnostic_unavailable",
                    "message": "診断の準備が整っていません。時間をおいてお試しください。",
                })
            response.headers["Cache-Control"] = "no-store"
            response.headers["Referrer-Policy"] = "no-referrer"
            return response

        return handler
