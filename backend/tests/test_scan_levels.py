from app.scans.levels import get_scan_level


def test_basic_level_is_passive_only_in_this_stage() -> None:
    level = get_scan_level("basic")

    assert level is not None
    assert level.display_name == "Lv.1"
    assert level.scan_mode == "baseline"
    assert level.active_rule_ids == ()
    assert "passive_scan" in level.check_ids


def test_unknown_level_returns_none() -> None:
    assert get_scan_level("advanced") is None
