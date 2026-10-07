import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime
from urllib.parse import urlencode

import aiohttp

from app.account_login.config import LoginSettings
from app.account_login.pkce_store import PkceStore
from app.account_login.protocol import (
    ATTEMPT_LIFETIME, CLIENT_ID, MAX_BODY_BYTES, SESSION_IDLE_LIFETIME,
    LoginError, digest, exchange_request, pkce_challenge, valid_token,
    validate_exchange_response,
)
from app.account_login.store import LoginStore


async def exchange_code(settings: LoginSettings, code: str, verifier: str) -> tuple[uuid.UUID, uuid.UUID]:
    body, headers, request_id = exchange_request(code, verifier, settings.callback_url,
                                                settings.key_id, settings.secret, datetime.now(UTC))
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5), trust_env=False,
                                        auto_decompress=False) as client:
            async with client.post(settings.exchange_url, data=body, headers=headers, allow_redirects=False) as response:
                if response.status != 200:
                    if response.status == 400:
                        raise LoginError(400, "invalid_grant", "本体のログイン情報が期限切れか、使用済みです。もう一度お試しください。")
                    raise LoginError(503, "login_unavailable", "本体とのログイン連携を確認できません。")
                if response.content_type != "application/json":
                    raise LoginError(503, "login_unavailable", "本体の応答を確認できません。")
                chunks = bytearray()
                async for chunk in response.content.iter_chunked(1024):
                    if len(chunks) + len(chunk) > MAX_BODY_BYTES:
                        raise LoginError(503, "login_unavailable", "本体の応答を確認できません。")
                    chunks.extend(chunk)
                return validate_exchange_response(bytes(chunks), request_id, settings.issuer, datetime.now(UTC))
    except (aiohttp.ClientError, TimeoutError):
        raise LoginError(503, "login_unavailable", "本体へ接続できません。ログインを最初からやり直してください。") from None


def cookie_hash(token: str | None) -> str | None:
    return digest(token) if valid_token(token) else None


class AccountLoginService:
    def __init__(self, settings: LoginSettings, store: LoginStore, pkce: PkceStore) -> None:
        self.settings, self.store, self.pkce = settings, store, pkce

    def start(self, previous_cookie: str | None, remote_ip: str, now: datetime) -> tuple[str, str]:
        bucket = hmac.new(self.settings.secret.encode(), b"login-start-rate-limit." + remote_ip.encode(), hashlib.sha256).hexdigest()
        self.store.rate_limit(bucket, now)
        state, verifier, browser = (secrets.token_urlsafe(32) for _ in range(3))
        attempt_id = uuid.uuid4()
        challenge = pkce_challenge(verifier)
        self.pkce.put(attempt_id, verifier)
        try:
            old_ids = self.store.create_attempt({
                "id": attempt_id, "state_hash": digest(state), "browser_token_hash": digest(browser),
                "pkce_challenge": challenge, "created_at": now, "expires_at": now + ATTEMPT_LIFETIME,
            }, cookie_hash(previous_cookie))
        except Exception:
            self.pkce.delete(attempt_id)
            raise
        for old_id in old_ids:
            self.pkce.delete(old_id)
        query = urlencode({"client_id": CLIENT_ID, "state": state, "code_challenge": challenge,
                           "code_challenge_method": "S256"})
        return self.settings.authorization_url + "?" + query, browser

    async def complete(self, values: dict, browser_cookie: str | None,
                       previous_session_cookie: str | None) -> tuple[dict, str | None]:
        if (not valid_token(values.get("state"))
                or (set(values) != {"state", "code"} and set(values) != {"state", "error"})
                or ("code" in values and not valid_token(values["code"]))
                or ("error" in values and values["error"] != "access_denied")):
            raise LoginError(400, "invalid_request", "ログイン情報の形式が正しくありません。")
        if not valid_token(browser_cookie):
            raise LoginError(403, "invalid_state", "ログインを開始したブラウザを確認できません。")
        now = datetime.now(UTC)
        cancelled = "error" in values
        attempt = self.store.claim_attempt(digest(values["state"]), digest(browser_cookie), now, cancelled)
        try:
            verifier = self.pkce.take(attempt["id"])
            if cancelled:
                return {"status": "cancelled", "redirect_path": "/"}, None
            if not valid_token(verifier) or pkce_challenge(verifier) != attempt["pkce_challenge"]:
                raise LoginError(410, "login_expired", "ログインの開始情報が期限切れです。もう一度お試しください。")
            subject, login_id = await exchange_code(self.settings, values["code"], verifier)
            token = secrets.token_urlsafe(32)
            self.store.finish_login(attempt["id"], self.settings.issuer, subject, login_id, digest(token),
                                    cookie_hash(previous_session_cookie), datetime.now(UTC))
            return {"status": "success", "redirect_path": "/check"}, token
        except LoginError as error:
            self.store.fail_attempt(attempt["id"], error.code, datetime.now(UTC))
            raise

    def session(self, token: str | None, now: datetime, touch: bool = False) -> dict | None:
        hashed = cookie_hash(token)
        return self.store.session(hashed, self.settings.issuer, now, touch) if hashed else None

    def logout(self, token: str | None, browser: str | None, now: datetime) -> None:
        for attempt_id in self.store.logout(cookie_hash(token), cookie_hash(browser), now):
            self.pkce.delete(attempt_id)

    @staticmethod
    def session_response(session: dict) -> dict:
        deadline = min(session["expires_at"], session["last_seen_at"] + SESSION_IDLE_LIFETIME)
        return {"authenticated": True, "account_id": str(session["account_id"]),
                "expires_at": deadline.isoformat().replace("+00:00", "Z")}
