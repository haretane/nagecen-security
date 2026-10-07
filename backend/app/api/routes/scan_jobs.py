import uuid
from datetime import UTC, datetime
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from psycopg import Connection
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator
from typing import Literal

from app.account_login.access import (
    AccountContext, AccountDiagnosticRoute, get_account_context, owner_filter, visible_record,
)

from app.database import get_connection
from app.scans.levels import SCAN_LEVELS, get_scan_level
from app.scans.result_presenter import (
    present_checks,
    present_findings,
    present_higher_level_checks,
    build_overall_ai_prompt,
)
from app.integrations.webhook import (
    assessment_payload,
    enqueue_webhook,
    verified_ownership,
    webhook_base_payload,
)
from app.security.auth_secret_store import (
    AuthenticationSecretStore,
    FormAuthenticationSecret,
    create_authentication_secret_store,
)
from app.security.url_scope import UrlScope, path_is_in_scope
from app.security.url_validator import UrlValidationError, validate_public_url


router = APIRouter(prefix="/api/scan-jobs", tags=["scan-jobs"], route_class=AccountDiagnosticRoute)
MAX_PENDING_SCAN_JOBS = 10


def cancellation_error_for_status(status: str) -> tuple[str, str] | None:
    if status == "queued":
        return None
    if status == "running":
        return ("scan_already_running", "診断処理はすでに開始されています。安全に終了するまでお待ちください。")
    return ("scan_not_cancellable", "この診断は現在中止できません。")


class FormAuthenticationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    login_url: str = Field(min_length=1, max_length=2048)
    identifier: str = Field(min_length=1, max_length=320)
    password: SecretStr = Field(min_length=1, max_length=1024)


class ScanJobCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verified_target_id: uuid.UUID
    level_id: str
    authorization_confirmed: bool
    active_scan_confirmed: bool
    data_change_risk_acknowledged: bool
    authentication_type: Literal["none", "form", "external", "special"]
    service_features: list[Literal[
        "view_only", "forms_or_posts", "login", "stores_data",
        "personal_data", "payments", "unknown",
    ]] = Field(min_length=1, max_length=7)
    form_authentication: FormAuthenticationInput | None = None

    @model_validator(mode="after")
    def require_matching_authentication_details(self):
        if len(self.service_features) != len(set(self.service_features)):
            raise ValueError("サービスの特徴を重複して選択できません。")
        if "unknown" in self.service_features and len(self.service_features) > 1:
            raise ValueError("「よく分からない」は単独で選択してください。")
        if "view_only" in self.service_features and len(self.service_features) > 1:
            raise ValueError("「見るだけのページ」は単独で選択してください。")
        if self.authentication_type == "form" and self.form_authentication is None:
            raise ValueError("通常ログインの情報を入力してください。")
        if self.authentication_type != "form" and self.form_authentication is not None:
            raise ValueError("選択したログイン方式では通常ログイン情報を送信できません。")
        return self


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
    checked_items: list[dict[str, str]]
    unchecked_items: list[dict[str, str]]
    incomplete_items: list[dict[str, str]]
    findings: list[dict]
    overall_ai_prompt: str | None
    attention_ai_prompt: str | None
    improvement_ai_prompt: str | None
    authentication_type: str
    authentication_status: str
    authentication_message: str
    service_features: list[str]


class ScanLevelResponse(BaseModel):
    id: str
    display_name: str
    description: str
    scan_mode: str
    check_ids: list[str]
    active_rule_ids: list[str]
    price_label: str
    available: bool


def _job_response(job: dict) -> ScanJobResponse:
    level = get_scan_level(job["level_id"])
    if level is None:
        raise HTTPException(status_code=500, detail="Unknown scan level")

    completed_ids = list(job["completed_check_ids"])
    incomplete_ids = [check_id for check_id in level.check_ids if check_id not in completed_ids]
    checked_items = present_checks(completed_ids)
    unchecked_items = present_higher_level_checks(level.id)
    incomplete_items = present_checks(incomplete_ids)
    findings = present_findings(job["report"], list(job.get("service_features") or [])) if job["status"] == "completed" else []
    attention_findings = [item for item in findings if item["presentation_group"] == "attention"]
    improvement_findings = [item for item in findings if item["presentation_group"] == "improvement"]
    authentication_messages = {
        "not_required": "ログインなしで見られる範囲を診断しました。",
        "not_attempted": "ログイン後のページは今回チェックしていません。公開ページの診断は実行しました。",
        "succeeded": "ログインに成功し、ログイン後のページも診断しました。",
        "failed": "ログインできなかったため、ログイン後のページはチェックしていません。公開ページの診断は実行しました。",
        "unsupported": "このログイン方式はMVP対象外のため、ログイン後のページはチェックしていません。公開ページの診断は実行しました。",
    }
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
        checked_items=checked_items,
        unchecked_items=unchecked_items,
        incomplete_items=incomplete_items,
        findings=findings,
        overall_ai_prompt=(
            build_overall_ai_prompt(
                target_url=job["target_url"],
                level_display_name=level.display_name,
                checked_items=checked_items,
                unchecked_items=unchecked_items,
                incomplete_items=incomplete_items,
                findings=findings,
            )
            if job["status"] == "completed"
            else None
        ),
        attention_ai_prompt=(
            build_overall_ai_prompt(
                target_url=job["target_url"],
                level_display_name=level.display_name,
                checked_items=checked_items,
                unchecked_items=unchecked_items,
                incomplete_items=incomplete_items,
                findings=attention_findings,
                prompt_purpose="attention",
            )
            if job["status"] == "completed"
            else None
        ),
        improvement_ai_prompt=(
            build_overall_ai_prompt(
                target_url=job["target_url"],
                level_display_name=level.display_name,
                checked_items=checked_items,
                unchecked_items=unchecked_items,
                incomplete_items=incomplete_items,
                findings=improvement_findings,
                prompt_purpose="improvement",
            )
            if job["status"] == "completed" and improvement_findings
            else None
        ),
        authentication_type=job["authentication_type"],
        authentication_status=job["authentication_status"],
        authentication_message=authentication_messages[job["authentication_status"]],
        service_features=list(job.get("service_features") or []),
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
            price_label=level.price_label,
            available=level.available,
        )
        for level in SCAN_LEVELS.values()
    ]


@router.post("", response_model=ScanJobResponse, status_code=201)
def create_scan_job(
    request: ScanJobCreateRequest,
    connection: Connection = Depends(get_connection),
    secret_store: AuthenticationSecretStore = Depends(create_authentication_secret_store),
    account: AccountContext | None = Depends(get_account_context),
) -> ScanJobResponse:
    level = get_scan_level(request.level_id)
    if level is None:
        raise HTTPException(
            status_code=422,
            detail={"code": "unknown_scan_level", "message": "診断レベルが正しくありません。"},
        )

    if not level.available:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "scan_level_unavailable",
                "message": "この診断レベルは現在準備中です。",
            },
        )

    if not request.authorization_confirmed:
        raise HTTPException(
            status_code=422,
            detail={"code": "authorization_required", "message": "所有または診断許可への同意が必要です。"},
        )

    if level.active_rule_ids and not request.active_scan_confirmed:
        raise HTTPException(
            status_code=422,
            detail={"code": "active_scan_consent_required", "message": "Active Scanの実行への同意が必要です。"},
        )

    if level.active_rule_ids and not request.data_change_risk_acknowledged:
        raise HTTPException(
            status_code=422,
            detail={"code": "data_change_acknowledgement_required", "message": "データ変更の可能性について確認が必要です。"},
        )

    predicate, owner_params = owner_filter(account)
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            SELECT *
            FROM verified_targets
            WHERE id = %s{predicate}
            """,
            (request.verified_target_id,) + owner_params,
        )
        verification = visible_record(cursor.fetchone(), account)

    if (
        verification is None
        or verification["status"] != "active"
        or (
            verification["valid_until"] is not None
            and verification["valid_until"] <= datetime.now(UTC)
        )
    ):
        raise HTTPException(
            status_code=422,
            detail={"code": "site_not_verified", "message": "所有確認が完了したサイトだけ診断できます。"},
        )

    form_secret = None
    if request.form_authentication is not None:
        try:
            validated_login_url = validate_public_url(request.form_authentication.login_url)
        except UrlValidationError as error:
            raise HTTPException(
                status_code=422,
                detail={"code": error.code, "message": f"ログインURL：{error.message}"},
            ) from error

        verified_scope = UrlScope(
            verification["verified_origin"],
            verification["verified_base_path"],
        )
        if not path_is_in_scope(validated_login_url.normalized_url, verified_scope):
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "login_url_out_of_scope",
                    "message": "ログインURLは所有確認済みのプロダクト範囲内を指定してください。",
                },
            )
        form_secret = FormAuthenticationSecret(
            login_url=validated_login_url.normalized_url,
            identifier=request.form_authentication.identifier,
            password=request.form_authentication.password.get_secret_value(),
        )

    job_id = uuid.uuid4()
    created_at = datetime.now(UTC)
    active_consent_at = created_at if level.active_rule_ids else None
    authentication_status = (
        "not_required"
        if request.authentication_type == "none"
        else "not_attempted"
        if request.authentication_type == "form"
        else "unsupported"
    )
    try:
        with connection.cursor() as cursor:
            # Serialize job creation so simultaneous requests cannot bypass the cap.
            cursor.execute("LOCK TABLE scan_jobs IN SHARE ROW EXCLUSIVE MODE")
            cursor.execute(
                "SELECT COUNT(*) AS count FROM scan_jobs WHERE status IN ('queued', 'running')"
            )
            if cursor.fetchone()["count"] >= MAX_PENDING_SCAN_JOBS:
                raise HTTPException(
                    status_code=429,
                    detail={
                        "code": "scan_queue_full",
                        "message": "診断が混み合っています。完了後にもう一度お試しください。",
                    },
                )
        if form_secret is not None:
            secret_store.put(job_id, form_secret)
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                INSERT INTO scan_jobs (
                    id, verified_target_id, level_id, status, target_url,
                    target_host, target_origin, target_base_path,
                    consent_confirmed_at, active_scan_consent_at,
                    data_change_risk_acknowledged_at, created_at,
                    authentication_type, authentication_status, service_features,
                    enabled_rule_ids, nagecen_handoff_id{', account_id' if account else ''}
                ) VALUES (%s, %s, %s, 'queued', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s{', %s' if account else ''})
                RETURNING *
                """,
                (
                    job_id,
                    request.verified_target_id,
                    level.id,
                    verification["verified_url"],
                    urlsplit(verification["verified_origin"]).hostname,
                    verification["verified_origin"],
                    verification["verified_base_path"],
                    created_at,
                    active_consent_at,
                    active_consent_at,
                    created_at,
                    request.authentication_type,
                    authentication_status,
                    Jsonb(request.service_features),
                    Jsonb(list(level.active_rule_ids)),
                    verification["nagecen_handoff_id"],
                ) + ((account.id,) if account else ()),
            )
            job = cursor.fetchone()
        connection.commit()
    except Exception:
        if form_secret is not None:
            secret_store.delete(job_id)
        raise

    return _job_response(job)


@router.get("/{job_id}", response_model=ScanJobResponse)
def get_scan_job(
    job_id: uuid.UUID,
    connection: Connection = Depends(get_connection),
    account: AccountContext | None = Depends(get_account_context),
) -> ScanJobResponse:
    predicate, owner_params = owner_filter(account)
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM scan_jobs WHERE id = %s" + predicate, (job_id,) + owner_params)
        job = visible_record(cursor.fetchone(), account)

    if job is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "scan_job_not_found", "message": "診断ジョブが見つかりません。"},
        )

    return _job_response(job)


@router.post("/{job_id}/cancel", response_model=ScanJobResponse)
def cancel_scan_job(
    job_id: uuid.UUID,
    connection: Connection = Depends(get_connection),
    secret_store: AuthenticationSecretStore = Depends(create_authentication_secret_store),
    account: AccountContext | None = Depends(get_account_context),
) -> ScanJobResponse:
    predicate, owner_params = owner_filter(account)
    finished_at = datetime.now(UTC)
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM scan_jobs WHERE id = %s" + predicate + " FOR UPDATE", (job_id,) + owner_params)
        job = visible_record(cursor.fetchone(), account)
        if job is None:
            raise HTTPException(
                status_code=404,
                detail={"code": "scan_job_not_found", "message": "診断ジョブが見つかりません。"},
            )
        cancellation_error = cancellation_error_for_status(job["status"])
        if cancellation_error is not None:
            raise HTTPException(
                status_code=409,
                detail={"code": cancellation_error[0], "message": cancellation_error[1]},
            )
        cursor.execute(
            """
            UPDATE scan_jobs
            SET status = 'cancelled', finished_at = %s,
                error_code = 'cancelled_by_user', error_message = '診断を開始前に中止しました。'
            WHERE id = %s
            RETURNING *
            """,
            (finished_at, job_id),
        )
        cancelled_job = cursor.fetchone()
        if job.get("nagecen_handoff_id") is not None:
            cursor.execute("SELECT * FROM nagecen_handoffs WHERE id = %s", (job["nagecen_handoff_id"],))
            handoff = cursor.fetchone()
            cursor.execute("SELECT * FROM verified_targets WHERE id = %s", (job["verified_target_id"],))
            target = cursor.fetchone()
            payload = webhook_base_payload(handoff, verified_ownership(target))
            payload["assessment"] = assessment_payload(cancelled_job, "cancelled")
            payload["error"] = {"code": "cancelled_by_user", "message": "利用者が診断を中止しました。"}
            enqueue_webhook(connection, handoff["id"], "security.assessment.cancelled", payload)
            cursor.execute(
                "UPDATE nagecen_handoffs SET status = 'cancelled', updated_at = %s WHERE id = %s",
                (finished_at, handoff["id"]),
            )
    secret_store.delete(job_id)
    connection.commit()
    return _job_response(cancelled_job)
