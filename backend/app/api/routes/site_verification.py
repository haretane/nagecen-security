import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Cookie, Depends, HTTPException
from psycopg import Connection
from pydantic import BaseModel, Field

from app.database import get_connection
from app.security.safe_http_client import SafeHttpError, fetch_public_html
from app.security.url_validator import UrlValidationError, validate_public_url
from app.security.url_scope import scope_from_validated_url
from app.security.verification_meta import (
    VERIFICATION_META_NAME,
    contains_verification_meta,
)
from app.integrations.nagecen import SESSION_COOKIE_NAME, get_handoff_from_session
from app.integrations.webhook import enqueue_webhook, verified_ownership, webhook_base_payload


router = APIRouter(prefix="/api/site-verifications", tags=["site-verification"])
TOKEN_LIFETIME = timedelta(minutes=30)
MAX_CHALLENGES_PER_HOST_PER_HOUR = 5
MAX_CHALLENGES_GLOBAL_PER_HOUR = 100
MAX_CONFIRMATION_ATTEMPTS = 20


class VerificationCreateRequest(BaseModel):
    url: str = Field(max_length=2_048)


class VerificationCreateResponse(BaseModel):
    verification_id: uuid.UUID
    target_url: str
    target_host: str
    token: str
    meta_tag: str
    created_at: datetime
    expires_at: datetime


class VerificationConfirmRequest(BaseModel):
    token: str = Field(min_length=20, max_length=200)


class VerificationConfirmResponse(BaseModel):
    verified: bool
    verified_target_id: uuid.UUID
    target_host: str
    verified_origin: str
    verified_base_path: str
    verified_at: datetime
    final_url: str
    redirect_count: int


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@router.post("", response_model=VerificationCreateResponse, status_code=201)
def create_verification(
    request: VerificationCreateRequest,
    connection: Connection = Depends(get_connection),
    nagecen_security_handoff_session: str | None = Cookie(default=None),
) -> VerificationCreateResponse:
    try:
        validated = validate_public_url(request.url)
    except UrlValidationError as error:
        raise HTTPException(
            status_code=422,
            detail={"code": error.code, "message": error.message},
        ) from error

    verification_id = uuid.uuid4()
    token = secrets.token_urlsafe(32)
    created_at = datetime.now(UTC)
    expires_at = created_at + TOKEN_LIFETIME
    handoff_id = None
    if nagecen_security_handoff_session:
        handoff = get_handoff_from_session(connection, nagecen_security_handoff_session)
        if validated.normalized_url != handoff["normalized_url"]:
            raise HTTPException(
                status_code=422,
                detail={"code": "handoff_url_mismatch", "message": "NAGeCenから連携されたURLと一致しません。"},
            )
        handoff_id = handoff["id"]

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT COUNT(*) AS count FROM verification_challenges WHERE created_at > %s",
            (created_at - timedelta(hours=1),),
        )
        if cursor.fetchone()["count"] >= MAX_CHALLENGES_GLOBAL_PER_HOUR:
            raise HTTPException(
                status_code=429,
                detail={"code": "verification_busy", "message": "所有確認が混み合っています。時間をおいてお試しください。"},
            )
        cursor.execute(
            "SELECT COUNT(*) AS count FROM verification_challenges WHERE target_host = %s AND created_at > %s",
            (validated.hostname, created_at - timedelta(hours=1)),
        )
        if cursor.fetchone()["count"] >= MAX_CHALLENGES_PER_HOST_PER_HOUR:
            raise HTTPException(
                status_code=429,
                detail={"code": "verification_rate_limited", "message": "このサイトの確認キーは短時間に複数回発行されています。しばらく待ってからお試しください。"},
            )
        cursor.execute(
            """
            INSERT INTO verification_challenges (
                id, target_url, target_host, token_hash, created_at, expires_at,
                nagecen_handoff_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                verification_id,
                validated.normalized_url,
                validated.hostname,
                _token_hash(token),
                created_at,
                expires_at,
                handoff_id,
            ),
        )
    meta_tag = f'<meta name="{VERIFICATION_META_NAME}" content="{token}">'
    return VerificationCreateResponse(
        verification_id=verification_id,
        target_url=validated.normalized_url,
        target_host=validated.hostname,
        token=token,
        meta_tag=meta_tag,
        created_at=created_at,
        expires_at=expires_at,
    )


@router.post("/{verification_id}/confirm", response_model=VerificationConfirmResponse)
async def confirm_verification(
    verification_id: uuid.UUID,
    request: VerificationConfirmRequest,
    connection: Connection = Depends(get_connection),
) -> VerificationConfirmResponse:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id, target_url, target_host, token_hash, expires_at,
                   verified_at, used_at, nagecen_handoff_id, confirmation_attempt_count
            FROM verification_challenges
            WHERE id = %s
            FOR UPDATE
            """,
            (verification_id,),
        )
        verification = cursor.fetchone()

    if verification is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "確認情報が見つかりません。"})

    now = datetime.now(UTC)
    if verification["expires_at"] <= now:
        raise HTTPException(status_code=410, detail={"code": "expired", "message": "確認キーの有効期限が切れています。再発行してください。"})

    if verification["used_at"] is not None:
        raise HTTPException(status_code=409, detail={"code": "already_used", "message": "この確認キーはすでに使用されています。"})

    if verification["confirmation_attempt_count"] >= MAX_CONFIRMATION_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail={"code": "confirmation_limit_reached", "message": "確認回数の上限に達しました。新しい確認キーを発行してください。"},
        )

    if not secrets.compare_digest(verification["token_hash"], _token_hash(request.token)):
        raise HTTPException(status_code=422, detail={"code": "token_mismatch", "message": "確認キーが一致しません。"})

    with connection.cursor() as cursor:
        cursor.execute(
            """
            UPDATE verification_challenges
            SET confirmation_attempt_count = confirmation_attempt_count + 1,
                last_confirmation_attempt_at = %s
            WHERE id = %s
            """,
            (now, verification_id),
        )
    # この後の対象サイト取得が失敗しても、アクセス回数は記録する。
    connection.commit()

    try:
        initial_validated_url = validate_public_url(verification["target_url"])
        initial_scope = scope_from_validated_url(initial_validated_url)
        response = await fetch_public_html(
            verification["target_url"],
            allowed_host=verification["target_host"],
            allowed_scope=initial_scope,
        )
    except (SafeHttpError, UrlValidationError) as error:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE verification_challenges SET last_error_code = %s WHERE id = %s",
                (error.code, verification_id),
            )
        connection.commit()
        raise HTTPException(status_code=422, detail={"code": error.code, "message": error.message}) from error

    final_host = validate_public_url(response.final_url).hostname
    if final_host != verification["target_host"]:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE verification_challenges SET last_error_code = %s WHERE id = %s",
                ("host_changed", verification_id),
            )
        connection.commit()
        raise HTTPException(
            status_code=422,
            detail={"code": "host_changed", "message": "所有確認済みにできるのは、最初に指定したホストだけです。"},
        )

    charset = "utf-8"
    html = response.body.decode(charset, errors="replace")
    if not contains_verification_meta(html, request.token):
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE verification_challenges SET last_error_code = %s WHERE id = %s",
                ("meta_not_found", verification_id),
            )
        connection.commit()
        raise HTTPException(
            status_code=422,
            detail={"code": "meta_not_found", "message": "HTMLの<head>内に確認用metaタグが見つかりませんでした。"},
        )

    verified_at = datetime.now(UTC)
    verified_target_id = uuid.uuid4()
    validated_final_url = validate_public_url(response.final_url)
    scope = scope_from_validated_url(validated_final_url)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            UPDATE verification_challenges
            SET verified_at = %s, used_at = %s, last_error_code = NULL
            WHERE id = %s
            """,
            (verified_at, verified_at, verification_id),
        )
        cursor.execute(
            """
            INSERT INTO verified_targets (
                id, verification_challenge_id, verified_url,
                verified_origin, verified_base_path, source, method,
                status, verified_at, last_revalidated_at, created_at,
                nagecen_handoff_id
            ) VALUES (%s, %s, %s, %s, %s, 'security', 'meta_tag',
                      'active', %s, %s, %s, %s)
            """,
            (
                verified_target_id,
                verification_id,
                response.final_url,
                scope.origin,
                scope.base_path,
                verified_at,
                verified_at,
                verified_at,
                verification["nagecen_handoff_id"],
            ),
        )
        if verification["nagecen_handoff_id"] is not None:
            cursor.execute(
                "SELECT * FROM nagecen_handoffs WHERE id = %s",
                (verification["nagecen_handoff_id"],),
            )
            handoff = cursor.fetchone()
            target = {
                "id": verified_target_id,
                "verified_url": response.final_url,
                "verified_origin": scope.origin,
                "verified_base_path": scope.base_path,
                "verified_at": verified_at,
            }
            enqueue_webhook(
                connection,
                handoff["id"],
                "security.verification.completed",
                webhook_base_payload(handoff, verified_ownership(target)),
            )
            cursor.execute(
                "UPDATE nagecen_handoffs SET status = 'verification_completed', updated_at = %s WHERE id = %s",
                (verified_at, handoff["id"]),
            )

    return VerificationConfirmResponse(
        verified=True,
        verified_target_id=verified_target_id,
        target_host=verification["target_host"],
        verified_origin=scope.origin,
        verified_base_path=scope.base_path,
        verified_at=verified_at,
        final_url=response.final_url,
        redirect_count=response.redirect_count,
    )
