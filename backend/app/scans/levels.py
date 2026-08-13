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
        # XSS Active Scanは次の開発段階で追加します。
        active_rule_ids=(),
    ),
}


def get_scan_level(level_id: str) -> ScanLevel | None:
    return SCAN_LEVELS.get(level_id)
