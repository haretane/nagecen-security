import io
import json
import os
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
from app.security.url_validator import validate_public_url
from app.worker.zap_report import parse_crawled_url_count, summarize_zap_report


ZAP_IMAGE = os.getenv("ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable")
WORKER_IMAGE = os.getenv("WORKER_IMAGE", "nagecen-security-backend:latest")
POLL_SECONDS = 2


def claim_job(connection) -> dict | None:
    with connection.cursor() as cursor:
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
            (datetime.now(UTC), datetime.now(UTC), job["id"]),
        )
    connection.commit()
    return job


def run_zap_job(client: docker.DockerClient, job: dict) -> tuple[dict, int, int, int]:
    level = get_scan_level(job["level_id"])
    if level is None or level.scan_mode != "baseline":
        raise RuntimeError("Unsupported scan level")

    validated = validate_public_url(job["target_url"])
    if validated.hostname != job["target_host"]:
        raise RuntimeError("Target host no longer matches verified host")

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

        command = [
            "zap-baseline.py",
            "-t", validated.normalized_url,
            "-m", str(level.spider_minutes),
            "-T", str(level.timeout_minutes),
            "-J", "report.json",
            "-I",
            "-z",
            "-config connection.proxyChain.enabled=true "
            "-config connection.proxyChain.hostName=egress-proxy "
            "-config connection.proxyChain.port=8080",
        ]
        container = client.containers.run(
            ZAP_IMAGE,
            command,
            name=zap_name,
            detach=True,
            network=network_name,
            volumes={volume_name: {"bind": "/zap/wrk", "mode": "rw"}},
            mem_limit="1536m",
            nano_cpus=1_000_000_000,
            pids_limit=512,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
        )
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
            raise RuntimeError(f"ZAP did not create a report (exit {exit_code})")
        finally:
            container.remove(force=True)

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


def complete_job(connection, job: dict, result: tuple[dict, int, int, int]) -> None:
    report, exit_code, alert_count, crawled_url_count = result
    level = get_scan_level(job["level_id"])
    with connection.cursor() as cursor:
        cursor.execute(
            """
            UPDATE scan_jobs
            SET status = 'completed', finished_at = %s, heartbeat_at = %s,
                spider_type = 'traditional', crawled_url_count = %s,
                completed_check_ids = %s, zap_exit_code = %s,
                alert_count = %s, report = %s
            WHERE id = %s
            """,
            (
                datetime.now(UTC), datetime.now(UTC), crawled_url_count,
                Jsonb(list(level.check_ids)), exit_code, alert_count,
                Jsonb(report), job["id"],
            ),
        )
    connection.commit()


def fail_job(connection, job_id: uuid.UUID, error: Exception) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            UPDATE scan_jobs
            SET status = 'failed', finished_at = %s, heartbeat_at = %s,
                failed_steps = %s, error_code = 'zap_execution_failed',
                error_message = %s
            WHERE id = %s
            """,
            (datetime.now(UTC), datetime.now(UTC), Jsonb(["passive_scan"]), str(error)[:500], job_id),
        )
    connection.commit()


def main() -> None:
    database_url = os.environ["DATABASE_URL"]
    client = docker.from_env()

    while True:
        with psycopg.connect(database_url, row_factory=dict_row) as connection:
            job = claim_job(connection)
            if job is None:
                time.sleep(POLL_SECONDS)
                continue
            try:
                complete_job(connection, job, run_zap_job(client, job))
            except Exception as error:
                fail_job(connection, job["id"], error)


if __name__ == "__main__":
    main()
