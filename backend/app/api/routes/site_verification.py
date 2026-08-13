import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from psycopg import Connection
from pydantic import BaseModel, Field

from app.database import get_connection
from app.security.safe_http_client import SafeHttpError, fetch_public_html
from app.security.url_validator import UrlValidationError, validate_public_url
from app.security.verification_meta import (
    VERIFICATION_META_NAME,
    contains_verification_meta,
)


router = APIRouter(prefix="/api/site-verifications", tags=["site-verification"])
TOKEN_LIFETIME = timedelta(minutes=30)


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
    target_host: str
    verified_at: datetime
    final_url: str
    redirect_count: int


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@router.post("", response_model=VerificationCreateResponse, status_code=201)
def create_verification(
    request: VerificationCreateRequest,
    connection: Connection = Depends(get_connection),
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

    with connection.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO site_verifications (
                id, target_url, target_host, token_hash, created_at, expires_at
            ) VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                verification_id,
                validated.normalized_url,
                validated.hostname,
                _token_hash(token),
                created_at,
                expires_at,
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
                   verified_at, used_at
            FROM site_verifications
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

    if not secrets.compare_digest(verification["token_hash"], _token_hash(request.token)):
        raise HTTPException(status_code=422, detail={"code": "token_mismatch", "message": "確認キーが一致しません。"})

    try:
        response = await fetch_public_html(
            verification["target_url"],
            allowed_host=verification["target_host"],
        )
    except (SafeHttpError, UrlValidationError) as error:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE site_verifications SET last_error_code = %s WHERE id = %s",
                (error.code, verification_id),
            )
        raise HTTPException(status_code=422, detail={"code": error.code, "message": error.message}) from error

    final_host = validate_public_url(response.final_url).hostname
    if final_host != verification["target_host"]:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE site_verifications SET last_error_code = %s WHERE id = %s",
                ("host_changed", verification_id),
            )
        raise HTTPException(
            status_code=422,
            detail={"code": "host_changed", "message": "所有確認済みにできるのは、最初に指定したホストだけです。"},
        )

    charset = "utf-8"
    html = response.body.decode(charset, errors="replace")
    if not contains_verification_meta(html, request.token):
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE site_verifications SET last_error_code = %s WHERE id = %s",
                ("meta_not_found", verification_id),
            )
        raise HTTPException(
            status_code=422,
            detail={"code": "meta_not_found", "message": "HTMLの<head>内に確認用metaタグが見つかりませんでした。"},
        )

    verified_at = datetime.now(UTC)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            UPDATE site_verifications
            SET verified_at = %s, used_at = %s, last_error_code = NULL
            WHERE id = %s
            """,
            (verified_at, verified_at, verification_id),
        )

    return VerificationConfirmResponse(
        verified=True,
        target_host=verification["target_host"],
        verified_at=verified_at,
        final_url=response.final_url,
        redirect_count=response.redirect_count,
    )
