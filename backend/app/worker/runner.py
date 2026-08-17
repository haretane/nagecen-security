import io
import json
import os
import re
import tarfile
import time
import uuid
from datetime import UTC, datetime

import docker
import psycopg
from docker.errors import ContainerError, DockerException
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app.scans.levels import get_scan_level
from app.security.auth_secret_store import create_authentication_secret_store
from app.security.auth_secret_store import FormAuthenticationSecret
from app.security.runtime_config import validate_production_config
from app.security.url_validator import validate_public_url
from app.security.url_scope import UrlScope, path_is_in_scope, scope_from_validated_url
from app.worker.zap_report import (
    keep_report_in_scope,
    parse_crawled_url_count,
    summarize_zap_report,
)
from app.integrations.webhook import (
    assessment_payload,
    deliver_due_webhook,
    enqueue_webhook,
    verified_ownership,
    webhook_base_payload,
)


ZAP_IMAGE = os.getenv("ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable")
WORKER_IMAGE = os.getenv("WORKER_IMAGE", "nagecen-security-backend:latest")
POLL_SECONDS = 2
# An authenticated attempt can be followed by one public fallback attempt.
STALE_JOB_MINUTES = 25
SPIDER_MAX_DEPTH = 3
SPIDER_MAX_CHILDREN = 20
SPIDER_MAX_PARSE_BYTES = 1_000_000
ACTIVE_RULE_NAMES = {
    "40012": "Reflected Cross Site Scripting",
    "40018": "SQL Injection",
    "90020": "Remote OS Command Injection",
    "6": "Path Traversal",
}


class AuthenticationFailedError(RuntimeError):
    pass


def authentication_succeeded(log_output: str) -> bool:
    return "Authentication successful." in log_output


def redact_authentication_secret(
    text: str,
    authentication_secret: FormAuthenticationSecret | None,
) -> str:
    if authentication_secret is None:
        return text
    redacted = text
    for sensitive_value in (
        authentication_secret.identifier,
        authentication_secret.password,
    ):
        if sensitive_value:
            redacted = redacted.replace(sensitive_value, "[REDACTED]")
    return redacted


def build_zap_automation_plan(
    target_url: str,
    scope: UrlScope,
    spider_minutes: int,
    timeout_minutes: int,
    active_rule_ids: tuple[str, ...] = (),
    active_scan_minutes: int = 3,
    active_rule_minutes: int = 2,
    request_delay_ms: int = 250,
    max_alerts_per_rule: int = 10,
    authentication_secret: FormAuthenticationSecret | None = None,
) -> dict:
    include_pattern = f"^{re.escape(scope.origin + scope.base_path)}.*$"
    jobs = [
        {
            "type": "passiveScan-config",
            "parameters": {"enableTags": False, "maxAlertsPerRule": 10},
        },
        {
            "type": "spider",
            "parameters": {
                "context": "verified-target",
                "url": target_url,
                "maxDuration": spider_minutes,
                "maxDepth": SPIDER_MAX_DEPTH,
                "maxChildren": SPIDER_MAX_CHILDREN,
                "maxParseSizeBytes": SPIDER_MAX_PARSE_BYTES,
                "threadCount": 2,
                "postForm": False,
                "parseRobotsTxt": False,
                "parseSitemapXml": False,
            },
        },
        {
            "type": "passiveScan-wait",
            "parameters": {"maxDuration": timeout_minutes},
        },
    ]
    if active_rule_ids:
        jobs.append(
            {
                "type": "activeScan",
                "parameters": {
                    "context": "verified-target",
                    "url": target_url,
                    "maxRuleDurationInMins": active_rule_minutes,
                    "maxScanDurationInMins": active_scan_minutes,
                    "delayInMs": request_delay_ms,
                    "threadPerHost": 1,
                    "maxAlertsPerRule": max_alerts_per_rule,
                    "addQueryParam": False,
                },
                "policyDefinition": {
                    "defaultStrength": "Low",
                    "defaultThreshold": "Off",
                    "rules": [
                        {
                            "id": int(rule_id),
                            "name": ACTIVE_RULE_NAMES[rule_id],
                            "strength": "Low",
                            "threshold": "Medium",
                        }
                        for rule_id in active_rule_ids
                    ],
                },
            }
        )
    if authentication_secret is not None:
        for job in jobs:
            if job["type"] in {"spider", "activeScan"}:
                job["parameters"]["user"] = "diagnosis-user"
    jobs.append(
        {
            "type": "report",
            "parameters": {
                "reportDir": "/zap/wrk/",
                "reportFile": "report.json",
                "reportTitle": "NAGeCen Security Scan Report",
                "template": "traditional-json",
            },
        }
    )
    context = {
        "name": "verified-target",
        "urls": [target_url],
        "includePaths": [include_pattern],
        "excludePaths": [],
    }
    if authentication_secret is not None:
        context.update({
            "authentication": {
                "method": "browser",
                "parameters": {
                    "loginPageUrl": authentication_secret.login_url,
                    "loginPageWait": 5,
                    "browserId": "firefox-headless",
                    "diagnostics": False,
                },
                "verification": {"method": "autodetect"},
            },
            "sessionManagement": {"method": "autodetect", "parameters": {}},
            "users": [{
                "name": "diagnosis-user",
                "credentials": {
                    "username": authentication_secret.identifier,
                    "password": authentication_secret.password,
                },
            }],
        })

    return {
        "env": {
            "contexts": [context],
            "parameters": {"failOnError": True, "progressToStdout": True},
        },
        "jobs": jobs,
    }


def automation_plan_archive(plan: dict) -> bytes:
    plan_bytes = json.dumps(plan, ensure_ascii=False).encode("utf-8")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("zap.yaml")
        info.size = len(plan_bytes)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(plan_bytes))
    return buffer.getvalue()


def fail_stale_jobs(connection) -> None:
    finished_at = datetime.now(UTC)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            UPDATE scan_jobs
            SET status = 'failed', finished_at = %s,
                failed_steps = %s,
                error_code = 'worker_interrupted',
                error_message = '診断処理が中断されました。もう一度お試しください。'
            WHERE status = 'running'
              AND heartbeat_at < %s - (%s * INTERVAL '1 minute')
            RETURNING *
            """,
            (finished_at, Jsonb(["passive_scan"]), finished_at, STALE_JOB_MINUTES),
        )
        stale_jobs = cursor.fetchall()
        for job in stale_jobs:
            if job.get("nagecen_handoff_id") is None:
                continue
            cursor.execute("SELECT * FROM nagecen_handoffs WHERE id = %s", (job["nagecen_handoff_id"],))
            handoff = cursor.fetchone()
            cursor.execute("SELECT * FROM verified_targets WHERE id = %s", (job["verified_target_id"],))
            target = cursor.fetchone()
            payload = webhook_base_payload(handoff, verified_ownership(target))
            payload["assessment"] = assessment_payload(job, "failed")
            payload["error"] = {
                "code": "worker_interrupted",
                "message": "診断処理が中断されました。",
            }
            enqueue_webhook(connection, handoff["id"], "security.assessment.failed", payload)
            cursor.execute(
                "UPDATE nagecen_handoffs SET status = 'failed', updated_at = %s WHERE id = %s",
                (finished_at, handoff["id"]),
            )
    connection.commit()


def claim_job(connection) -> dict | None:
    with connection.cursor() as cursor:
        started_at = datetime.now(UTC)
        cursor.execute(
            """
            SELECT * FROM scan_jobs
            WHERE status = 'queued'
            ORDER BY created_at
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            """
        )
        job = cursor.fetchone()
        if job is None:
            return None
        cursor.execute(
            """
            UPDATE scan_jobs
            SET status = 'running', started_at = %s, heartbeat_at = %s
            WHERE id = %s
            """,
            (started_at, started_at, job["id"]),
        )
    connection.commit()
    job["started_at"] = started_at
    return job


def run_zap_job(
    client: docker.DockerClient,
    job: dict,
    authentication_secret: FormAuthenticationSecret | None = None,
) -> tuple[dict, int, int, int]:
    level = get_scan_level(job["level_id"])
    if level is None or level.scan_mode != "baseline":
        raise RuntimeError("Unsupported scan level")

    validated = validate_public_url(job["target_url"])
    if validated.hostname != job["target_host"]:
        raise RuntimeError("Target host no longer matches verified host")
    verified_scope = UrlScope(job["target_origin"], job["target_base_path"])
    actual_scope = scope_from_validated_url(validated)
    if actual_scope != verified_scope or not path_is_in_scope(
        validated.normalized_url,
        verified_scope,
    ):
        raise RuntimeError("Target URL no longer matches verified scope")

    suffix = str(job["id"]).replace("-", "")[:12]
    network_name = f"nagecen-zap-{suffix}"
    proxy_name = f"nagecen-egress-{suffix}"
    zap_name = f"nagecen-zap-run-{suffix}"
    volume_name = f"nagecen-zap-report-{suffix}"
    network = None
    proxy = None
    report_volume = None

    try:
        network = client.networks.create(network_name, internal=True, check_duplicate=True)
        report_volume = client.volumes.create(name=volume_name, labels={"app": "nagecen-security"})
        client.containers.run(
            ZAP_IMAGE,
            ["chmod", "0777", "/zap/wrk"],
            user="0",
            network_disabled=True,
            volumes={volume_name: {"bind": "/zap/wrk", "mode": "rw"}},
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            remove=True,
        )
        proxy = client.containers.run(
            WORKER_IMAGE,
            ["python", "-m", "app.worker.egress_proxy", "--allowed-host", validated.hostname],
            name=proxy_name,
            detach=True,
            network="bridge",
            mem_limit="128m",
            nano_cpus=250_000_000,
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
        )
        network.connect(proxy, aliases=["egress-proxy"])
        time.sleep(0.5)

        plan = build_zap_automation_plan(
            validated.normalized_url,
            verified_scope,
            level.spider_minutes,
            level.timeout_minutes,
            level.active_rule_ids,
            level.active_scan_minutes,
            level.active_rule_minutes,
            level.request_delay_ms,
            level.max_alerts_per_rule,
            authentication_secret,
        )
        command = [
            "zap.sh",
            "-cmd",
            "-autorun", "/zap/wrk/zap.yaml",
            "-config", "connection.proxyChain.enabled=true",
            "-config", "connection.proxyChain.hostName=egress-proxy",
            "-config", "connection.proxyChain.port=8080",
        ]
        container = client.containers.create(
            ZAP_IMAGE,
            command,
            name=zap_name,
            network=network_name,
            volumes={volume_name: {"bind": "/zap/wrk", "mode": "rw"}},
            mem_limit="1536m",
            nano_cpus=1_000_000_000,
            pids_limit=512,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
        )
        container.put_archive("/zap/wrk", automation_plan_archive(plan))
        container.start()
        result = container.wait(timeout=(level.timeout_minutes + 2) * 60)
        exit_code = int(result["StatusCode"])
        log_output = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        try:
            archive_stream, _archive_info = container.get_archive("/zap/wrk/report.json")
            archive_bytes = b"".join(archive_stream)
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as archive:
                report_member = next(
                    (member for member in archive.getmembers() if member.isfile()),
                    None,
                )
                report_file = archive.extractfile(report_member) if report_member else None
                if report_file is None:
                    raise RuntimeError("ZAP report archive was empty")
                report = json.loads(report_file.read().decode("utf-8"))
        except (DockerException, tarfile.TarError, json.JSONDecodeError) as error:
            # Authentication add-ons may encode credentials in unexpected forms.
            # Do not propagate any ZAP log tail from an authenticated attempt.
            safe_log_output = (
                ""
                if authentication_secret is not None
                else redact_authentication_secret(log_output, authentication_secret)
            )
            useful_log_lines = [
                line.strip()
                for line in safe_log_output.splitlines()
                if line.strip()
            ]
            log_tail = " | ".join(useful_log_lines[-8:])[-1200:]
            detail = f": {log_tail}" if log_tail else ""
            raise RuntimeError(
                f"ZAP did not create a report (exit {exit_code}){detail}"
            ) from error
        finally:
            container.remove(force=True)

        if authentication_secret is not None and not authentication_succeeded(log_output):
            raise AuthenticationFailedError("Automatic login could not be confirmed")

        report = keep_report_in_scope(report, verified_scope)
        alert_count, detected_url_count = summarize_zap_report(report)
        crawled_url_count = parse_crawled_url_count(log_output) or detected_url_count
        return report, exit_code, alert_count, crawled_url_count
    finally:
        for container_name in (zap_name, proxy_name):
            try:
                client.containers.get(container_name).remove(force=True)
            except DockerException:
                pass
        if network is not None:
            try:
                network.remove()
            except DockerException:
                pass
        if report_volume is not None:
            try:
                report_volume.remove(force=True)
            except DockerException:
                pass


def complete_job(
    connection,
    job: dict,
    result: tuple[dict, int, int, int],
    authentication_status: str,
) -> None:
    report, exit_code, alert_count, crawled_url_count = result
    level = get_scan_level(job["level_id"])
    failed_steps = ["authentication"] if authentication_status == "failed" else []
    with connection.cursor() as cursor:
        cursor.execute(
            """
            UPDATE scan_jobs
            SET status = 'completed', finished_at = %s, heartbeat_at = %s,
                spider_type = 'traditional', crawled_url_count = %s,
                completed_check_ids = %s, zap_exit_code = %s,
                alert_count = %s, report = %s,
                authentication_status = %s, failed_steps = %s
            WHERE id = %s
            """,
            (
                datetime.now(UTC), datetime.now(UTC), crawled_url_count,
                Jsonb(list(level.check_ids)), exit_code, alert_count,
                Jsonb(report), authentication_status, Jsonb(failed_steps), job["id"],
            ),
        )
        if job.get("nagecen_handoff_id") is not None:
            cursor.execute("SELECT * FROM nagecen_handoffs WHERE id = %s", (job["nagecen_handoff_id"],))
            handoff = cursor.fetchone()
            cursor.execute("SELECT * FROM verified_targets WHERE id = %s", (job["verified_target_id"],))
            target = cursor.fetchone()
            completed_job = {**job, **{
                "finished_at": datetime.now(UTC),
                "authentication_status": authentication_status,
                "alert_count": alert_count,
                "completed_check_ids": list(level.check_ids),
                "timed_out_steps": [],
                "failed_steps": failed_steps,
            }}
            payload = webhook_base_payload(handoff, verified_ownership(target))
            payload["assessment"] = assessment_payload(completed_job, "completed")
            enqueue_webhook(connection, handoff["id"], "security.assessment.completed", payload)
            cursor.execute(
                "UPDATE nagecen_handoffs SET status = 'assessment_completed', updated_at = %s WHERE id = %s",
                (datetime.now(UTC), handoff["id"]),
            )
    connection.commit()


def fail_job(connection, job_id: uuid.UUID, error: Exception) -> None:
    finished_at = datetime.now(UTC)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            UPDATE scan_jobs
            SET status = 'failed', finished_at = %s, heartbeat_at = %s,
                failed_steps = %s, error_code = 'zap_execution_failed',
                error_message = %s
            WHERE id = %s
            """,
            (finished_at, finished_at, Jsonb(["passive_scan"]), str(error)[:500], job_id),
        )
        cursor.execute("SELECT * FROM scan_jobs WHERE id = %s", (job_id,))
        job = cursor.fetchone()
        if job.get("nagecen_handoff_id") is not None:
            cursor.execute("SELECT * FROM nagecen_handoffs WHERE id = %s", (job["nagecen_handoff_id"],))
            handoff = cursor.fetchone()
            cursor.execute("SELECT * FROM verified_targets WHERE id = %s", (job["verified_target_id"],))
            target = cursor.fetchone()
            payload = webhook_base_payload(handoff, verified_ownership(target))
            payload["assessment"] = assessment_payload(job, "failed")
            payload["error"] = {
                "code": "assessment_failed",
                "message": "診断を完了できませんでした。",
            }
            enqueue_webhook(connection, handoff["id"], "security.assessment.failed", payload)
            cursor.execute(
                "UPDATE nagecen_handoffs SET status = 'failed', updated_at = %s WHERE id = %s",
                (finished_at, handoff["id"]),
            )
    connection.commit()


def main() -> None:
    validate_production_config(component="worker")
    database_url = os.environ["DATABASE_URL"]
    client = docker.from_env()
    secret_store = create_authentication_secret_store()

    while True:
        with psycopg.connect(database_url, row_factory=dict_row) as connection:
            deliver_due_webhook(connection)
            fail_stale_jobs(connection)
            job = claim_job(connection)
            if job is None:
                time.sleep(POLL_SECONDS)
                continue
            authentication_secret = None
            authentication_status = job["authentication_status"]
            if job["authentication_type"] == "form":
                authentication_secret = secret_store.take(job["id"])
                if authentication_secret is None:
                    authentication_status = "failed"
            try:
                if authentication_secret is not None:
                    try:
                        result = run_zap_job(client, job, authentication_secret)
                        authentication_status = "succeeded"
                    except Exception:
                        authentication_status = "failed"
                        result = run_zap_job(client, job)
                    finally:
                        del authentication_secret
                else:
                    result = run_zap_job(client, job)
                complete_job(connection, job, result, authentication_status)
            except Exception as error:
                fail_job(connection, job["id"], error)


if __name__ == "__main__":
    main()
