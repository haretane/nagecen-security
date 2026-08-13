import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from psycopg import Connection
from psycopg.types.json import Jsonb
from pydantic import BaseModel

from app.database import get_connection
from app.scans.levels import SCAN_LEVELS, get_scan_level


router = APIRouter(prefix="/api/scan-jobs", tags=["scan-jobs"])


class ScanJobCreateRequest(BaseModel):
    site_verification_id: uuid.UUID
    level_id: str
    authorization_confirmed: bool


class ScanJobResponse(BaseModel):
    id: uuid.UUID
    level_id: str
    level_display_name: str
    status: str
    target_url: str
    target_host: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    crawled_url_count: int
    alert_count: int
    completed_check_ids: list[str]
    timed_out_steps: list[str]
    failed_steps: list[str]
    error_message: str | None


class ScanLevelResponse(BaseModel):
    id: str
    display_name: str
    description: str
    scan_mode: str
    check_ids: list[str]
    active_rule_ids: list[str]


def _job_response(job: dict) -> ScanJobResponse:
    level = get_scan_level(job["level_id"])
    if level is None:
        raise HTTPException(status_code=500, detail="Unknown scan level")

    return ScanJobResponse(
        id=job["id"],
        level_id=job["level_id"],
        level_display_name=level.display_name,
        status=job["status"],
        target_url=job["target_url"],
        target_host=job["target_host"],
        created_at=job["created_at"],
        started_at=job["started_at"],
        finished_at=job["finished_at"],
        crawled_url_count=job["crawled_url_count"],
        alert_count=job["alert_count"],
        completed_check_ids=job["completed_check_ids"],
        timed_out_steps=job["timed_out_steps"],
        failed_steps=job["failed_steps"],
        error_message=job["error_message"],
    )


@router.get("/levels", response_model=list[ScanLevelResponse])
def list_scan_levels() -> list[ScanLevelResponse]:
    return [
        ScanLevelResponse(
            id=level.id,
            display_name=level.display_name,
            description=level.description,
            scan_mode=level.scan_mode,
            check_ids=list(level.check_ids),
            active_rule_ids=list(level.active_rule_ids),
        )
        for level in SCAN_LEVELS.values()
    ]


@router.post("", response_model=ScanJobResponse, status_code=201)
def create_scan_job(
    request: ScanJobCreateRequest,
    connection: Connection = Depends(get_connection),
) -> ScanJobResponse:
    level = get_scan_level(request.level_id)
    if level is None:
        raise HTTPException(
            status_code=422,
            detail={"code": "unknown_scan_level", "message": "診断レベルが正しくありません。"},
        )

    if not request.authorization_confirmed:
        raise HTTPException(
            status_code=422,
            detail={"code": "authorization_required", "message": "所有または診断許可への同意が必要です。"},
        )

    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id, target_url, target_host, verified_at
            FROM site_verifications
            WHERE id = %s
            """,
            (request.site_verification_id,),
        )
        verification = cursor.fetchone()

    if verification is None or verification["verified_at"] is None:
        raise HTTPException(
            status_code=422,
            detail={"code": "site_not_verified", "message": "所有確認が完了したサイトだけ診断できます。"},
        )

    job_id = uuid.uuid4()
    created_at = datetime.now(UTC)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO scan_jobs (
                id, site_verification_id, level_id, status, target_url,
                target_host, consent_confirmed_at, created_at,
                enabled_rule_ids
            ) VALUES (%s, %s, %s, 'queued', %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                job_id,
                request.site_verification_id,
                level.id,
                verification["target_url"],
                verification["target_host"],
                created_at,
                created_at,
                Jsonb(list(level.active_rule_ids)),
            ),
        )
        job = cursor.fetchone()

    return _job_response(job)


@router.get("/{job_id}", response_model=ScanJobResponse)
def get_scan_job(
    job_id: uuid.UUID,
    connection: Connection = Depends(get_connection),
) -> ScanJobResponse:
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM scan_jobs WHERE id = %s", (job_id,))
        job = cursor.fetchone()

    if job is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "scan_job_not_found", "message": "診断ジョブが見つかりません。"},
        )

    return _job_response(job)
