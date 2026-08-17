from app.scans.levels import get_scan_level


def test_basic_level_is_passive_and_free() -> None:
    level = get_scan_level("basic")

    assert level is not None
    assert level.display_name == "Lv.1"
    assert level.scan_mode == "baseline"
    assert level.active_rule_ids == ()
    assert level.price_label == "無料"
    assert level.available is True
    assert "passive_scan" in level.check_ids


def test_unknown_level_returns_none() -> None:
    assert get_scan_level("unknown") is None


def test_xss_level_enables_only_reflected_xss_and_is_free() -> None:
    level = get_scan_level("xss")

    assert level is not None
    assert level.display_name == "Lv.2"
    assert level.active_rule_ids == ("40012",)
    assert level.price_label == "無料"
    assert level.available is True


def test_advanced_level_adds_only_planned_active_rules() -> None:
    level = get_scan_level("advanced")

    assert level is not None
    assert level.display_name == "Lv.3"
    assert level.active_rule_ids == ("40012", "40018", "90020", "6")
    assert level.request_delay_ms == 500
    assert level.price_label == "有料・準備中"
    assert level.available is False
