import base64
import hashlib
import hmac
import json
import re
import uuid
from datetime import UTC, datetime, timedelta


CLIENT_ID = "nagecen-security"
ATTEMPT_LIFETIME = timedelta(minutes=10)
SESSION_LIFETIME = timedelta(hours=8)
SESSION_IDLE_LIFETIME = timedelta(hours=1)
MAX_BODY_BYTES = 8192
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class LoginError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(code)  # Never put input, tokens or upstream exceptions here.
        self.status = status
        self.code = code
        self.message = message


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def valid_token(value: object) -> bool:
    return isinstance(value, str) and TOKEN_PATTERN.fullmatch(value) is not None


def pkce_challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")


def _unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def parse_json(raw: bytes) -> dict:
    try:
        if len(raw) > MAX_BODY_BYTES:
            raise ValueError("too large")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if not isinstance(value, dict):
            raise ValueError("not an object")
        return value
    except (ValueError, RecursionError):
        raise LoginError(400, "invalid_request", "ログイン情報の形式が正しくありません。") from None


def exchange_request(code: str, verifier: str, callback_url: str, key_id: str, secret: str,
                     now: datetime) -> tuple[bytes, dict[str, str], str]:
    request_id = str(uuid.uuid4())
    body = json.dumps({
        "version": "1", "request_id": request_id, "client_id": CLIENT_ID,
        "code": code, "code_verifier": verifier, "redirect_uri": callback_url,
    }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(now.timestamp()))
    signature = hmac.new(secret.encode("utf-8"),
                         b"nagecen-security-login-v1." + timestamp.encode("ascii") + b"." + body,
                         hashlib.sha256).hexdigest()
    return body, {
        "Content-Type": "application/json",
        "X-Security-Login-Key-Id": key_id,
        "X-Security-Login-Timestamp": timestamp,
        "X-Security-Login-Signature": "sha256=" + signature,
    }, request_id


def canonical_uuid4(value: object) -> uuid.UUID:
    try:
        if not isinstance(value, str):
            raise ValueError("not a string")
        parsed = uuid.UUID(value)
        if parsed.version != 4 or str(parsed) != value:
            raise ValueError("not canonical UUID v4")
        return parsed
    except (ValueError, AttributeError):
        raise LoginError(503, "login_unavailable", "本体のログイン情報を確認できません。") from None


def validate_exchange_response(raw: bytes, request_id: str, issuer: str, now: datetime) -> tuple[uuid.UUID, uuid.UUID]:
    try:
        values = parse_json(raw)
        if set(values) != {"status", "version", "request_id", "login_id", "issuer", "audience", "subject", "issued_at", "validated_at"}:
            raise ValueError("unexpected fields")
        if (values["status"], values["version"], values["request_id"], values["issuer"], values["audience"]) != ("success", "1", request_id, issuer, CLIENT_ID):
            raise ValueError("response mismatch")
        subject = canonical_uuid4(values["subject"])
        login_id = canonical_uuid4(values["login_id"])
        dates = []
        for key in ("issued_at", "validated_at"):
            text = values[key]
            if not isinstance(text, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", text):
                raise ValueError("not UTC")
            dates.append(datetime.fromisoformat(text.replace("Z", "+00:00")))
        issued, validated = dates
        if issued > validated or validated > now + timedelta(seconds=60) or issued < now - timedelta(minutes=3):
            raise ValueError("response time mismatch")
        return subject, login_id
    except (LoginError, ValueError, TypeError, KeyError):
        raise LoginError(503, "login_unavailable", "本体のログイン情報を確認できません。") from None


def session_is_active(session: dict, now: datetime) -> bool:
    return (session["revoked_at"] is None and session.get("disabled_at") is None
            and session["created_at"] <= now < session["expires_at"]
            and now - SESSION_IDLE_LIFETIME < session["last_seen_at"] <= now)
