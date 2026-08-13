from app.worker.zap_report import parse_crawled_url_count, summarize_zap_report


def test_summarizes_alerts_and_unique_urls() -> None:
    report = {
        "site": [
            {
                "alerts": [
                    {
                        "instances": [
                            {"uri": "https://example.com/"},
                            {"uri": "https://example.com/login"},
                        ]
                    },
                    {"instances": [{"uri": "https://example.com/"}]},
                ]
            }
        ]
    }

    assert summarize_zap_report(report) == (3, 2)


def test_empty_report_has_zero_counts() -> None:
    assert summarize_zap_report({}) == (0, 0)


def test_parses_crawled_url_count_from_baseline_log() -> None:
    assert parse_crawled_url_count("Spider complete\nTotal of 12 URLs\nPASS: example") == 12


def test_missing_crawled_url_count_returns_none() -> None:
    assert parse_crawled_url_count("ZAP stopped before spider summary") is None
