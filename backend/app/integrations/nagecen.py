import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import quote

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response
from psycopg import Connection
from pydantic import BaseModel, ConfigDict, ValidationError

from app.database import get_connection
from app.security.url_scope import scope_from_validated_url
from app.security.url_validator import UrlValidationError, validate_public_url


router = APIRouter(prefix="/api/integrations/nagecen", tags=["nagecen-integration"])
SIGNATURE_MAX_AGE_SECONDS = 5 * 60
HANDOFF_TOKEN_LIFETIME = timedelta(minutes=10)
SESSION_LIFETIME = timedelta(minutes=60)
SESSION_COOKIE_NAME = "nagecen_security_handoff_session"


class ProductInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    status: Literal["draft", "published"]
    owner_subject: str
    url: str


class OwnershipInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["unverified"]
    verified_url: None
    verified_at: None


class ReturnContextInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["product_draft", "product_edit", "mypage"]
    id: str


class HandoffInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal["1"]
    jti: uuid.UUID
    intent: Literal["verify_only", "verify_and_scan"]
    product: ProductInput
    ownership: OwnershipInput
    return_context: ReturnContextInput


class TokenExchangeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str


class HandoffContextResponse(BaseModel):
    handoff_id: uuid.UUID
    intent: str
    product_id: str
    product_status: str
    product_url: str
    normalized_url: str
    target_origin: str
    target_base_path: str
    return_context_type: str
    return_context_id: str
    status: str
    return_url: str


def handoff_context_response(handoff: dict) -> HandoffContextResponse:
    nagecen_frontend = os.getenv("NAGECEN_FRONTEND_URL", "http://localhost:5173/nagecen").rstrip("/")
    if handoff["return_context_type"] == "product_draft":
        return_path = "/post"
        return_query = (
            f"draft={quote(str(handoff['return_context_id']))}"
            "&security_return=completed"
        )
    else:
        return_path = "/mypage"
        return_query = "security_return=completed"
    return HandoffContextResponse(
        handoff_id=handoff["id"],
        intent=handoff["intent"],
        product_id=handoff["product_id"],
        product_status=handoff["product_status"],
        product_url=handoff["product_url"],
        normalized_url=handoff["normalized_url"],
        target_origin=handoff["target_origin"],
        target_base_path=handoff["target_base_path"],
        return_context_type=handoff["return_context_type"],
        return_context_id=handoff["return_context_id"],
        status=handoff["status"],
        return_url=f"{nagecen_frontend}{return_path}?{return_query}",
    )


def integration_error(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_handoff_signature(
    raw_body: bytes,
    timestamp: str | None,
    signature: str | None,
    key_id: str | None,
    now: int | None = None,
) -> None:
    if not timestamp or not signature or not key_id:
        raise integration_error(401, "missing_signature", "連携情報の署名がありません。")
    expected_key_id = os.getenv("NAGECEN_TO_SECURITY_KEY_ID", "local-v1")
    if key_id != expected_key_id:
        raise integration_error(401, "unknown_key_id", "連携情報の鍵IDを確認できません。")
    try:
        timestamp_value = int(timestamp)
    except ValueError as error:
        raise integration_error(408, "signature_timestamp_out_of_range", "連携情報の有効期限を確認できません。") from error
    current_time = int(time.time()) if now is None else now
    if abs(current_time - timestamp_value) > SIGNATURE_MAX_AGE_SECONDS:
        raise integration_error(408, "signature_timestamp_out_of_range", "連携情報の有効期限が切れています。")
    secret = os.getenv("NAGECEN_TO_SECURITY_HMAC_SECRET", "")
    if len(secret) < 32:
        raise integration_error(503, "service_unavailable", "Security連携の設定が完了していません。")
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        timestamp.encode("ascii") + b"." + raw_body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise integration_error(401, "invalid_signature", "連携情報の署名を確認できません。")


def validate_handoff_consistency(payload: HandoffInput) -> None:
    if payload.product.id != payload.return_context.id:
        raise integration_error(422, "product_id_mismatch", "プロダクトIDが一致しません。")
    allowed_return_types = (
        {"product_draft"} if payload.product.status == "draft" else {"product_edit", "mypage"}
    )
    if payload.return_context.type not in allowed_return_types:
        raise integration_error(422, "invalid_return_context", "戻り先の種類がプロダクト状態と一致しません。")
    if not payload.product.id or len(payload.product.id) > 64:
        raise integration_error(422, "product_id_mismatch", "プロダクトIDが正しくありません。")
    if not payload.product.owner_subject or len(payload.product.owner_subject) > 128:
        raise integration_error(422, "invalid_product_owner", "所有者情報が正しくありません。")


@router.post("/handoffs", status_code=201)
async def create_handoff(
    request: Request,
    connection: Connection = Depends(get_connection),
    x_nagecen_timestamp: str | None = Header(default=None),
    x_nagecen_signature: str | None = Header(default=None),
    x_nagecen_key_id: str | None = Header(default=None),
) -> dict:
    raw_body = await request.body()
    verify_handoff_signature(
        raw_body,
        x_nagecen_timestamp,
        x_nagecen_signature,
        x_nagecen_key_id,
    )
    try:
        decoded = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise integration_error(400, "invalid_json", "JSONを読み取れません。") from error
    try:
        payload = HandoffInput.model_validate(decoded)
    except ValidationError as error:
        raise integration_error(422, "invalid_handoff", "連携情報の項目が正しくありません。") from error
    validate_handoff_consistency(payload)

    try:
        validated_url = validate_public_url(payload.product.url)
    except UrlValidationError as error:
        code = "unsafe_product_url" if error.code in {
            "private_network_address", "localhost_not_allowed", "port_not_allowed",
        } else "invalid_product_url"
        raise integration_error(422, code, error.message) from error
    scope = scope_from_validated_url(validated_url)
    now = datetime.now(UTC)
    handoff_id = uuid.uuid4()
    handoff_token = secrets.token_urlsafe(32)
    token_expires_at = now + HANDOFF_TOKEN_LIFETIME

    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM nagecen_handoffs WHERE jti = %s", (payload.jti,))
        if cursor.fetchone() is not None:
            raise integration_error(409, "handoff_already_used", "この連携情報はすでに使用されています。")
        cursor.execute(
            """
            SELECT id FROM nagecen_handoffs
            WHERE product_id = %s AND status IN ('created', 'active')
              AND handoff_token_expires_at > %s
            LIMIT 1
            """,
            (payload.product.id, now),
        )
        if cursor.fetchone() is not None:
            raise integration_error(409, "product_handoff_conflict", "このプロダクトのSecurity連携はすでに進行中です。")
        cursor.execute(
            """
            INSERT INTO nagecen_handoffs (
                id, jti, version, intent, product_id, product_status,
                owner_subject, product_url, normalized_url, target_origin,
                target_base_path, return_context_type, return_context_id,
                request_key_id, request_timestamp, request_body_sha256,
                handoff_token_hash, handoff_token_expires_at, status,
                created_at, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, 'created', %s, %s
            )
            """,
            (
                handoff_id, payload.jti, payload.version, payload.intent,
                payload.product.id, payload.product.status, payload.product.owner_subject,
                payload.product.url, validated_url.normalized_url, scope.origin,
                scope.base_path, payload.return_context.type, payload.return_context.id,
                x_nagecen_key_id, int(x_nagecen_timestamp), hashlib.sha256(raw_body).hexdigest(),
                token_hash(handoff_token), token_expires_at, now, now,
            ),
        )

    frontend_url = os.getenv("SECURITY_FRONTEND_URL", "http://localhost:5174").rstrip("/")
    return {
        "handoff_id": handoff_id,
        "handoff_token": handoff_token,
        "security_url": f"{frontend_url}/integrations/nagecen?token={quote(handoff_token)}",
        "expires_at": token_expires_at,
    }


@router.post("/handoff-token/exchange", response_model=HandoffContextResponse)
def exchange_handoff_token(
    request: TokenExchangeInput,
    response: Response,
    connection: Connection = Depends(get_connection),
) -> HandoffContextResponse:
    now = datetime.now(UTC)
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM nagecen_handoffs WHERE handoff_token_hash = %s FOR UPDATE",
            (token_hash(request.token),),
        )
        handoff = cursor.fetchone()
        if handoff is None:
            raise integration_error(404, "handoff_token_not_found", "連携情報が見つかりません。")
        if handoff["handoff_token_used_at"] is not None:
            raise integration_error(409, "handoff_token_already_used", "この連携URLはすでに使用されています。")
        if handoff["handoff_token_expires_at"] <= now:
            raise integration_error(410, "handoff_token_expired", "連携URLの有効期限が切れています。")
        session_id = uuid.uuid4()
        session_token = secrets.token_urlsafe(32)
        session_expires_at = now + SESSION_LIFETIME
        cursor.execute(
            """
            INSERT INTO nagecen_handoff_sessions (
                id, handoff_id, session_token_hash, created_at, expires_at, last_seen_at
            ) VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (session_id, handoff["id"], token_hash(session_token), now, session_expires_at, now),
        )
        cursor.execute(
            """
            UPDATE nagecen_handoffs
            SET handoff_token_used_at = %s, status = 'active', updated_at = %s
            WHERE id = %s
            """,
            (now, now, handoff["id"]),
        )
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        max_age=int(SESSION_LIFETIME.total_seconds()),
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        samesite="lax",
        path="/",
    )
    handoff["status"] = "active"
    return handoff_context_response(handoff)


def get_handoff_from_session(
    connection: Connection,
    session_token: str | None,
) -> dict:
    if not session_token:
        raise integration_error(401, "handoff_session_required", "NAGeCenから連携を開始してください。")
    now = datetime.now(UTC)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT h.* FROM nagecen_handoff_sessions s
            JOIN nagecen_handoffs h ON h.id = s.handoff_id
            WHERE s.session_token_hash = %s AND s.revoked_at IS NULL AND s.expires_at > %s
            """,
            (token_hash(session_token), now),
        )
        handoff = cursor.fetchone()
        if handoff is None:
            raise integration_error(401, "handoff_session_expired", "連携セッションの有効期限が切れています。")
        cursor.execute(
            "UPDATE nagecen_handoff_sessions SET last_seen_at = %s WHERE session_token_hash = %s",
            (now, token_hash(session_token)),
        )
    return handoff


@router.get("/session", response_model=HandoffContextResponse)
def get_handoff_session(
    connection: Connection = Depends(get_connection),
    nagecen_security_handoff_session: str | None = Cookie(default=None),
) -> HandoffContextResponse:
    handoff = get_handoff_from_session(connection, nagecen_security_handoff_session)
    return handoff_context_response(handoff)
