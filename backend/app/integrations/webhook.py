import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta

from psycopg.types.json import Jsonb


RETRY_DELAYS = (10, 60, 300, 1800)
MAX_ATTEMPTS = 5
RETRYABLE_STATUSES = {408, 425, 429, *range(500, 600)}


def iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def sign_webhook(raw_body: bytes, timestamp: str, secret: str) -> str:
    if len(secret) < 32:
        raise RuntimeError("Webhook secret is not configured")
    return "sha256=" + hmac.new(
        secret.encode("utf-8"), timestamp.encode("ascii") + b"." + raw_body, hashlib.sha256
    ).hexdigest()


def enqueue_webhook(connection, handoff_id: uuid.UUID, event_type: str, payload: dict) -> uuid.UUID:
    event_id = uuid.uuid4()
    payload = {**payload, "event_id": str(event_id), "event_type": event_type}
    now = datetime.now(UTC)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO nagecen_webhook_outbox (
                id, handoff_id, event_id, event_type, payload, status,
                attempt_count, next_attempt_at, created_at
            ) VALUES (%s, %s, %s, %s, %s, 'pending', 0, %s, %s)
            """,
            (uuid.uuid4(), handoff_id, event_id, event_type, Jsonb(payload), now, now),
        )
    return event_id


def webhook_base_payload(handoff: dict, ownership: dict) -> dict:
    return {
        "version": "1",
        "occurred_at": iso_utc(datetime.now(UTC)),
        "handoff_id": str(handoff["id"]),
        "jti": str(handoff["jti"]),
        "product": {"id": handoff["product_id"], "url": handoff["product_url"]},
        "ownership": ownership,
        "assessment": None,
        "error": None,
    }


def verified_ownership(target: dict) -> dict:
    return {
        "status": "verified",
        "verified_target_id": str(target["id"]),
        "verified_url": target["verified_url"],
        "verified_origin": target["verified_origin"],
        "verified_base_path": target["verified_base_path"],
        "verified_at": iso_utc(target["verified_at"]),
    }


def assessment_payload(job: dict, status: str) -> dict:
    return {
        "status": status,
        "scan_job_id": str(job["id"]),
        "level_id": job["level_id"],
        "started_at": iso_utc(job["started_at"]),
        "finished_at": iso_utc(job["finished_at"]),
        "authentication_status": job["authentication_status"],
        "alert_count": job["alert_count"],
        "completed_check_ids": list(job["completed_check_ids"]),
        "timed_out_steps": list(job["timed_out_steps"]),
        "failed_steps": list(job["failed_steps"]),
    }


def deliver_due_webhook(connection) -> bool:
    now = datetime.now(UTC)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT * FROM nagecen_webhook_outbox
            WHERE status = 'pending' AND next_attempt_at <= %s
            ORDER BY next_attempt_at
            FOR UPDATE SKIP LOCKED LIMIT 1
            """,
            (now,),
        )
        item = cursor.fetchone()
    if item is None:
        return False

    callback_url = os.getenv("NAGECEN_CALLBACK_URL", "")
    secret = os.getenv("SECURITY_TO_NAGECEN_HMAC_SECRET", "")
    key_id = os.getenv("SECURITY_TO_NAGECEN_KEY_ID", "security-local-v1")
    raw_body = json.dumps(item["payload"], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    http_status = None
    error_code = None
    retryable = True
    try:
        request = urllib.request.Request(
            callback_url,
            raw_body,
            {
                "Content-Type": "application/json",
                "X-NAGeCen-Security-Timestamp": timestamp,
                "X-NAGeCen-Security-Signature": sign_webhook(raw_body, timestamp, secret),
                "X-NAGeCen-Security-Key-Id": key_id,
            },
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            http_status = response.status
        delivered = 200 <= http_status < 300
        retryable = http_status in RETRYABLE_STATUSES
    except urllib.error.HTTPError as error:
        http_status = error.code
        delivered = False
        retryable = http_status in RETRYABLE_STATUSES
        error_code = "http_error"
    except (urllib.error.URLError, TimeoutError, ValueError, RuntimeError):
        delivered = False
        error_code = "connection_error"

    attempts = item["attempt_count"] + 1
    with connection.cursor() as cursor:
        if delivered:
            cursor.execute(
                """UPDATE nagecen_webhook_outbox SET status = 'delivered', attempt_count = %s,
                   last_attempt_at = %s, delivered_at = %s, last_http_status = %s,
                   last_error_code = NULL WHERE id = %s""",
                (attempts, now, now, http_status, item["id"]),
            )
        elif not retryable or attempts >= MAX_ATTEMPTS:
            cursor.execute(
                """UPDATE nagecen_webhook_outbox SET status = 'delivery_failed', attempt_count = %s,
                   last_attempt_at = %s, last_http_status = %s, last_error_code = %s WHERE id = %s""",
                (attempts, now, http_status, error_code, item["id"]),
            )
        else:
            delay = RETRY_DELAYS[attempts - 1]
            cursor.execute(
                """UPDATE nagecen_webhook_outbox SET attempt_count = %s, last_attempt_at = %s,
                   next_attempt_at = %s, last_http_status = %s, last_error_code = %s WHERE id = %s""",
                (attempts, now, now + timedelta(seconds=delay), http_status, error_code, item["id"]),
            )
    connection.commit()
    return True
