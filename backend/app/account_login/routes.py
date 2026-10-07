import os
from datetime import UTC, datetime

import psycopg
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from psycopg.rows import dict_row
from redis import Redis
from redis.exceptions import RedisError

from app.account_login.config import LoginSettings, get_login_settings
from app.account_login.pkce_store import PkceStore
from app.account_login.protocol import ATTEMPT_LIFETIME, MAX_BODY_BYTES, SESSION_LIFETIME, LoginError, parse_json
from app.account_login.service import AccountLoginService
from app.account_login.store import LoginStore


class LoginRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request: Request):
            try:
                response = await original(request)
            except LoginError as error:
                response = JSONResponse(status_code=error.status,
                                        content={"status": "error", "code": error.code, "message": error.message})
            except (psycopg.Error, RedisError, KeyError):
                # Do not expose connection strings, request bodies, or Redis keys.
                response = JSONResponse(status_code=503, content={"status": "error", "code": "login_unavailable",
                                                                  "message": "ログインの準備が整っていません。時間をおいてお試しください。"})
            response.headers["Cache-Control"] = "no-store"
            response.headers["Referrer-Policy"] = "no-referrer"
            return response

        return handler


router = APIRouter(prefix="/api/auth", tags=["account-login"], route_class=LoginRoute)


def get_login_store(settings: LoginSettings = Depends(get_login_settings)):
    with psycopg.connect(os.environ["DATABASE_URL"], row_factory=dict_row, autocommit=True,
                         connect_timeout=3) as connection:
        yield LoginStore(connection)


def get_pkce_store(settings: LoginSettings = Depends(get_login_settings)) -> PkceStore:
    return PkceStore(Redis.from_url(os.environ["AUTH_SECRET_STORE_URL"], decode_responses=True,
                                   socket_connect_timeout=2, socket_timeout=2))


def get_login_service(settings: LoginSettings = Depends(get_login_settings),
                      store: LoginStore = Depends(get_login_store),
                      pkce: PkceStore = Depends(get_pkce_store)) -> AccountLoginService:
    return AccountLoginService(settings, store, pkce)


def check_origin(request: Request, settings: LoginSettings, optional: bool = False) -> None:
    origins = request.headers.getlist("origin")
    if optional and not origins:
        return
    if origins != [settings.frontend_origin]:
        raise LoginError(403, "csrf_failed", "Securityの画面から操作してください。")


async def read_json(request: Request) -> dict:
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise LoginError(400, "invalid_request", "JSON形式で送信してください。")
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > MAX_BODY_BYTES:
            raise LoginError(400, "invalid_request", "ログイン情報の形式が正しくありません。")
        raw.extend(chunk)
    return parse_json(bytes(raw))


def set_cookie(response: JSONResponse, name: str, value: str, seconds: int, settings: LoginSettings) -> None:
    response.set_cookie(name, value, max_age=seconds, secure=settings.cookie_secure,
                        httponly=True, samesite="lax", path="/")


def clear_cookie(response: JSONResponse, name: str, settings: LoginSettings) -> None:
    response.delete_cookie(name, secure=settings.cookie_secure, httponly=True, samesite="lax", path="/")


@router.post("/nagecen/start")
async def start_login(request: Request, service: AccountLoginService = Depends(get_login_service)) -> JSONResponse:
    check_origin(request, service.settings)
    if await read_json(request) != {}:
        raise LoginError(400, "invalid_request", "ログイン開始に追加の項目は指定できません。")
    # request.client is intentionally not replaced by an untrusted forwarded IP.
    authorization_url, browser = service.start(request.cookies.get(service.settings.start_cookie),
                                                request.client.host if request.client else "unknown", datetime.now(UTC))
    response = JSONResponse({"authorization_url": authorization_url})
    set_cookie(response, service.settings.start_cookie, browser, int(ATTEMPT_LIFETIME.total_seconds()), service.settings)
    return response


@router.post("/nagecen/complete")
async def complete_login(request: Request, service: AccountLoginService = Depends(get_login_service)) -> JSONResponse:
    check_origin(request, service.settings)
    values = await read_json(request)
    result, token = await service.complete(values, request.cookies.get(service.settings.start_cookie),
                                           request.cookies.get(service.settings.session_cookie))
    response = JSONResponse(result)
    clear_cookie(response, service.settings.start_cookie, service.settings)
    if token is not None:
        set_cookie(response, service.settings.session_cookie, token, int(SESSION_LIFETIME.total_seconds()), service.settings)
    return response


@router.get("/session")
def login_session(request: Request, service: AccountLoginService = Depends(get_login_service)) -> JSONResponse:
    check_origin(request, service.settings, optional=True)
    token = request.cookies.get(service.settings.session_cookie)
    # Polling the status alone must not keep a session alive indefinitely.
    session = service.session(token, datetime.now(UTC), touch=False)
    response = JSONResponse(service.session_response(session) if session else {"authenticated": False})
    if token is not None and session is None:
        clear_cookie(response, service.settings.session_cookie, service.settings)
    return response


@router.post("/logout")
async def logout(request: Request, service: AccountLoginService = Depends(get_login_service)) -> JSONResponse:
    check_origin(request, service.settings)
    if await read_json(request) != {}:
        raise LoginError(400, "invalid_request", "ログアウトに追加の項目は指定できません。")
    service.logout(request.cookies.get(service.settings.session_cookie),
                   request.cookies.get(service.settings.start_cookie), datetime.now(UTC))
    response = JSONResponse({"status": "success", "authenticated": False})
    clear_cookie(response, service.settings.session_cookie, service.settings)
    clear_cookie(response, service.settings.start_cookie, service.settings)
    return response
