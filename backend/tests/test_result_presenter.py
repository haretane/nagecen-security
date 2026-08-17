from app.scans.result_presenter import (
    html_to_text,
    present_checks,
    present_findings,
    present_higher_level_checks,
    build_overall_ai_prompt,
)


def test_presents_and_sorts_findings_for_beginners() -> None:
    report = {"site": [{"alerts": [
        {
            "pluginid": "99999",
            "riskcode": "1",
            "name": "Technical name",
            "desc": "<p>Plain <strong>description</strong>.</p>",
            "solution": "<p>Fix the setting.</p>",
            "instances": [{"uri": "https://example.com/app/", "method": "GET"}],
        },
        {
            "pluginid": "10055",
            "riskcode": "2",
            "name": "CSP: Failure to Define Directive with No Fallback",
            "instances": [
                {"uri": "https://example.com/app/a", "method": "GET", "param": "CSP"},
                {"uri": "https://example.com/app/a", "method": "GET", "param": "CSP"},
            ],
        },
    ]}]}

    findings = present_findings(report)

    assert findings[0]["risk_label"] == "中"
    assert findings[0]["priority_label"] == "優先して確認"
    assert findings[0]["title"] == "CSPの一部項目が未設定です"
    assert findings[0]["technical_title"] == "CSP: Failure to Define Directive with No Fallback"
    assert findings[0]["location_count"] == 1
    assert findings[0]["presentation_group"] == "improvement"
    assert findings[1]["presentation_group"] == "attention"
    assert findings[1]["description"] == "Plain description ."
    assert "対応が必要かどうか" in findings[0]["ai_prompt"]
    assert "すぐに修正を始めず" in findings[0]["ai_prompt"]
    assert "CSP: Failure to Define Directive" in findings[0]["ai_prompt"]


def test_invalid_report_is_empty_and_html_is_text_only() -> None:
    assert present_findings(None) == []
    assert html_to_text("<script>alert(1)</script><p>説明</p>") == "alert(1) 説明"


def test_diagnostic_only_finding_is_presented_as_reference() -> None:
    findings = present_findings({"site": [{"alerts": [{
        "pluginid": "10109",
        "riskcode": "0",
        "name": "Modern Web Application",
        "instances": [],
    }]}]})

    assert findings[0]["presentation_group"] == "reference"


def test_sensitive_service_raises_cors_and_cache_visibility() -> None:
    report = {"site": [{"alerts": [
        {"pluginid": "40040", "riskcode": "2", "name": "Cross-Domain Misconfiguration", "instances": []},
        {"pluginid": "10015", "riskcode": "0", "name": "Re-examine Cache-control Directives", "instances": []},
    ]}]}

    findings = present_findings(report, ["login", "stores_data"])
    groups = {item["technical_title"]: item["presentation_group"] for item in findings}

    assert groups["Cross-Domain Misconfiguration"] == "attention"
    assert groups["Re-examine Cache-control Directives"] == "improvement"


def test_presents_check_labels() -> None:
    assert present_checks(["passive_scan"]) == [
        {"id": "passive_scan", "label": "通信内容の受動診断"}
    ]


def test_basic_level_shows_advanced_checks_as_not_checked() -> None:
    checks = present_higher_level_checks("basic")

    assert [check["id"] for check in checks] == [
        "reflected_xss_active_scan",
        "sql_injection_active_scan",
        "os_command_injection_active_scan",
        "path_traversal_active_scan",
    ]
    assert [check["id"] for check in present_higher_level_checks("xss")] == [
        "sql_injection_active_scan",
        "os_command_injection_active_scan",
        "path_traversal_active_scan",
    ]
    assert present_higher_level_checks("advanced") == []


def test_builds_overall_prompt_without_raw_report_data() -> None:
    prompt = build_overall_ai_prompt(
        target_url="https://example.com/app/",
        level_display_name="Lv.1",
        checked_items=present_checks(["passive_scan"]),
        unchecked_items=present_checks(["reflected_xss_active_scan"]),
        incomplete_items=[],
        findings=[],
    )

    assert "対象URL：https://example.com/app/" in prompt
    assert "通信内容の受動診断" in prompt
    assert "反射型XSS" in prompt
    assert "安全が保証されたとは表現しない" in prompt
    assert "対応困難" in prompt
    assert "今回の診断対象外：XSS" in prompt


def test_overall_prompt_includes_context_needed_to_review_a_finding() -> None:
    finding = {
        "priority_label": "優先して確認",
        "risk_label": "中",
        "title": "安全設定を確認してください",
        "technical_title": "Technical Header Name",
        "description": "設定が見つかりませんでした。",
        "solution": "利用環境の設定を確認してください。",
        "location_count": 1,
    }
    prompt = build_overall_ai_prompt(
        target_url="https://example.com/",
        level_display_name="Lv.1",
        checked_items=[],
        unchecked_items=[],
        incomplete_items=[],
        findings=[finding],
    )

    assert "技術上の名称：Technical Header Name" in prompt
    assert "説明：設定が見つかりませんでした。" in prompt
    assert "対応の方向性：利用環境の設定を確認してください。" in prompt
