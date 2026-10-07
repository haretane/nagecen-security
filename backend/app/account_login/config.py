import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.account_login.protocol import LoginError
from app.security.runtime_config import LOCAL_SECRET_MARKERS


@dataclass(frozen=True)
class LoginSettings:
    frontend_origin: str
    authorization_url: str
    exchange_url: str
    issuer: str
    callback_url: str
    key_id: str
    secret: str = field(repr=False)
    cookie_secure: bool = False

    @property
    def start_cookie(self) -> str:
        return "__Host-nagecen_security_account_start" if self.cookie_secure else "nagecen_security_account_start_dev"

    @property
    def session_cookie(self) -> str:
        return "__Host-nagecen_security_account_session" if self.cookie_secure else "nagecen_security_account_session_dev"


def get_login_settings() -> LoginSettings:
    if os.getenv("SECURITY_ACCOUNT_LOGIN_ENABLED", "false").lower() != "true":
        raise LoginError(503, "login_unavailable", "アカウント連携はまだ有効になっていません。")
    # This first implementation is intentionally local-only. Diagnostic API
    # account guards and callback UI must ship together before production release.
    if os.getenv("APP_ENV", "production").lower() != "development":
        raise LoginError(503, "login_unavailable", "アカウント連携はまだ本番公開されていません。")
    try:
        frontend = os.environ["SECURITY_FRONTEND_URL"].rstrip("/")
        authorization = os.environ["NAGECEN_LOGIN_AUTHORIZE_URL"]
        exchange = os.environ["NAGECEN_LOGIN_EXCHANGE_URL"]
        issuer = os.environ["NAGECEN_ACCOUNT_ISSUER"]
        key_id = os.environ["SECURITY_TO_NAGECEN_LOGIN_KEY_ID"]
        secret = os.environ["SECURITY_TO_NAGECEN_LOGIN_HMAC_SECRET"]
        for url in (frontend, authorization, exchange, issuer):
            if any(ord(character) <= 32 for character in url) or "\\" in url:
                raise ValueError("invalid endpoint characters")
            parsed = urlsplit(url)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or parsed.query or parsed.fragment):
                raise ValueError("invalid endpoint")
            _ = parsed.port
            if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "host.docker.internal"}:
                raise ValueError("non-local HTTP")
        if urlsplit(frontend).path or not issuer.endswith("/"):
            raise ValueError("invalid frontend or issuer")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", key_id) or not 32 <= len(secret) <= 4096:
            raise ValueError("invalid key")
        if any(marker in secret.lower() for marker in LOCAL_SECRET_MARKERS):
            raise ValueError("placeholder key")
        if any(secret == os.getenv(name) for name in ("NAGECEN_TO_SECURITY_HMAC_SECRET", "SECURITY_TO_NAGECEN_HMAC_SECRET")):
            raise ValueError("key reuse")
        # Except for Docker's local host alias, all provider URLs must point to
        # the same issuer authority. Never sign/send to a browser-selected URL.
        authority = urlsplit(issuer).netloc
        if urlsplit(authorization).netloc != authority:
            raise ValueError("authorization authority mismatch")
        if urlsplit(exchange).netloc != authority and urlsplit(exchange).hostname != "host.docker.internal":
            raise ValueError("exchange authority mismatch")
        return LoginSettings(frontend, authorization, exchange, issuer,
                             frontend + "/auth/nagecen/callback", key_id, secret,
                             os.getenv("COOKIE_SECURE", "false").lower() == "true")
    except (KeyError, ValueError):
        raise LoginError(503, "login_unavailable", "アカウント連携の設定が完了していません。") from None
