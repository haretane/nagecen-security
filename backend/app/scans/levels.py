from dataclasses import dataclass


@dataclass(frozen=True)
class ScanLevel:
    id: str
    display_name: str
    description: str
    scan_mode: str
    spider_minutes: int
    timeout_minutes: int
    check_ids: tuple[str, ...]
    active_rule_ids: tuple[str, ...]
    active_scan_minutes: int
    active_rule_minutes: int
    request_delay_ms: int
    max_alerts_per_rule: int
    price_label: str
    available: bool


SCAN_LEVELS = {
    "basic": ScanLevel(
        id="basic",
        display_name="Lv.1",
        description="基本セーフティチェック",
        scan_mode="baseline",
        spider_minutes=1,
        timeout_minutes=5,
        check_ids=(
            "passive_scan",
            "security_headers",
            "cookie_settings",
            "mixed_content",
            "information_disclosure",
            "traditional_spider",
        ),
        active_rule_ids=(),
        active_scan_minutes=3,
        active_rule_minutes=2,
        request_delay_ms=250,
        max_alerts_per_rule=10,
        price_label="無料",
        available=True,
    ),
    "xss": ScanLevel(
        id="xss",
        display_name="Lv.2",
        description="XSS診断付きチェック",
        scan_mode="baseline",
        spider_minutes=1,
        timeout_minutes=5,
        check_ids=(
            "passive_scan",
            "security_headers",
            "cookie_settings",
            "mixed_content",
            "information_disclosure",
            "traditional_spider",
            "reflected_xss_active_scan",
        ),
        active_rule_ids=("40012",),
        active_scan_minutes=3,
        active_rule_minutes=2,
        request_delay_ms=250,
        max_alerts_per_rule=10,
        price_label="無料",
        available=True,
    ),
    "advanced": ScanLevel(
        id="advanced",
        display_name="Lv.3",
        description="より踏み込んだチェック",
        scan_mode="baseline",
        spider_minutes=1,
        timeout_minutes=8,
        check_ids=(
            "passive_scan",
            "security_headers",
            "cookie_settings",
            "mixed_content",
            "information_disclosure",
            "traditional_spider",
            "reflected_xss_active_scan",
            "sql_injection_active_scan",
            "os_command_injection_active_scan",
            "path_traversal_active_scan",
        ),
        active_rule_ids=("40012", "40018", "90020", "6"),
        active_scan_minutes=6,
        active_rule_minutes=2,
        request_delay_ms=500,
        max_alerts_per_rule=10,
        price_label="有料・準備中",
        available=False,
    ),
}


def get_scan_level(level_id: str) -> ScanLevel | None:
    return SCAN_LEVELS.get(level_id)
