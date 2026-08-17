from datetime import UTC, datetime, timedelta

import io
import json
import tarfile

from app.security.url_scope import UrlScope
from app.security.auth_secret_store import FormAuthenticationSecret
from app.worker.runner import (
    STALE_JOB_MINUTES,
    automation_plan_archive,
    build_zap_automation_plan,
    authentication_succeeded,
    redact_authentication_secret,
)


def test_stale_job_threshold_is_longer_than_normal_polling() -> None:
    now = datetime.now(UTC)
    stale_at = now - timedelta(minutes=STALE_JOB_MINUTES)

    assert stale_at < now
    assert STALE_JOB_MINUTES >= 5


def test_automation_plan_limits_spider_to_verified_base_path() -> None:
    plan = build_zap_automation_plan(
        "https://haretane.github.io/kadai_02/",
        UrlScope("https://haretane.github.io", "/kadai_02/"),
        spider_minutes=1,
        timeout_minutes=5,
    )

    context = plan["env"]["contexts"][0]
    spider = plan["jobs"][1]["parameters"]
    assert context["urls"] == ["https://haretane.github.io/kadai_02/"]
    assert context["includePaths"] == [
        r"^https://haretane\.github\.io/kadai_02/.*$"
    ]
    assert spider["context"] == "verified-target"
    assert spider["url"] == "https://haretane.github.io/kadai_02/"
    assert spider["maxDepth"] == 3
    assert spider["maxChildren"] == 20
    assert spider["threadCount"] == 2
    assert spider["postForm"] is False
    assert spider["parseRobotsTxt"] is False
    assert spider["parseSitemapXml"] is False


def test_automation_plan_archive_contains_json_compatible_yaml() -> None:
    plan = build_zap_automation_plan(
        "https://example.com/app/",
        UrlScope("https://example.com", "/app/"),
        spider_minutes=1,
        timeout_minutes=5,
    )

    with tarfile.open(fileobj=io.BytesIO(automation_plan_archive(plan))) as archive:
        archived_plan = json.load(archive.extractfile("zap.yaml"))

    assert archived_plan == plan


def test_active_scan_enables_only_reflected_xss_with_strict_limits() -> None:
    plan = build_zap_automation_plan(
        "https://example.com/app/",
        UrlScope("https://example.com", "/app/"),
        spider_minutes=1,
        timeout_minutes=5,
        active_rule_ids=("40012",),
    )

    active_scan = next(job for job in plan["jobs"] if job["type"] == "activeScan")
    assert active_scan["parameters"]["context"] == "verified-target"
    assert active_scan["parameters"]["threadPerHost"] == 1
    assert active_scan["parameters"]["delayInMs"] == 250
    assert active_scan["parameters"]["maxScanDurationInMins"] == 3
    assert active_scan["policyDefinition"]["defaultThreshold"] == "Off"
    assert active_scan["policyDefinition"]["rules"] == [{
        "id": 40012,
        "name": "Reflected Cross Site Scripting",
        "strength": "Low",
        "threshold": "Medium",
    }]


def test_advanced_plan_enables_only_four_approved_rules() -> None:
    plan = build_zap_automation_plan(
        "https://example.com/app/",
        UrlScope("https://example.com", "/app/"),
        spider_minutes=1,
        timeout_minutes=8,
        active_rule_ids=("40012", "40018", "90020", "6"),
        active_scan_minutes=6,
        active_rule_minutes=2,
        request_delay_ms=500,
        max_alerts_per_rule=10,
    )

    active_scan = next(job for job in plan["jobs"] if job["type"] == "activeScan")
    assert active_scan["policyDefinition"]["defaultThreshold"] == "Off"
    assert [rule["id"] for rule in active_scan["policyDefinition"]["rules"]] == [
        40012, 40018, 90020, 6,
    ]
    assert active_scan["parameters"]["delayInMs"] == 500
    assert active_scan["parameters"]["maxScanDurationInMins"] == 6


def test_authenticated_plan_uses_browser_autodetection_and_authenticated_user() -> None:
    secret = FormAuthenticationSecret(
        login_url="https://example.com/app/login",
        identifier="diagnosis-user@example.com",
        password="temporary-password",
    )
    plan = build_zap_automation_plan(
        "https://example.com/app/",
        UrlScope("https://example.com", "/app/"),
        spider_minutes=1,
        timeout_minutes=5,
        authentication_secret=secret,
    )

    context = plan["env"]["contexts"][0]
    spider = next(job for job in plan["jobs"] if job["type"] == "spider")
    assert context["authentication"]["method"] == "browser"
    assert context["authentication"]["verification"]["method"] == "autodetect"
    assert context["sessionManagement"]["method"] == "autodetect"
    assert context["users"][0]["credentials"]["username"] == secret.identifier
    assert spider["parameters"]["user"] == "diagnosis-user"


def test_authentication_success_is_read_from_zap_output() -> None:
    assert authentication_succeeded("Authentication successful.\nSpider started")
    assert not authentication_succeeded("Authentication failed.\nSpider started")


def test_credentials_are_redacted_from_error_output() -> None:
    secret = FormAuthenticationSecret(
        login_url="https://example.com/app/login",
        identifier="private-user@example.com",
        password="very-secret-password",
    )

    safe_output = redact_authentication_secret(
        "login private-user@example.com failed with very-secret-password",
        secret,
    )

    assert secret.identifier not in safe_output
    assert secret.password not in safe_output
    assert safe_output.count("[REDACTED]") == 2
