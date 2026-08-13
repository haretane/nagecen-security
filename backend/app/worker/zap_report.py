from collections.abc import Mapping
import re


def summarize_zap_report(report: Mapping) -> tuple[int, int]:
    sites = report.get("site", [])
    alert_count = 0
    urls: set[str] = set()

    for site in sites if isinstance(sites, list) else []:
        alerts = site.get("alerts", []) if isinstance(site, dict) else []
        for alert in alerts if isinstance(alerts, list) else []:
            instances = alert.get("instances", []) if isinstance(alert, dict) else []
            alert_count += len(instances) if instances else 1
            for instance in instances if isinstance(instances, list) else []:
                if isinstance(instance, dict) and instance.get("uri"):
                    urls.add(instance["uri"])

    return alert_count, len(urls)


def parse_crawled_url_count(log_output: str) -> int | None:
    matches = re.findall(r"Total of\s+(\d+)\s+URLs?", log_output, flags=re.IGNORECASE)
    return int(matches[-1]) if matches else None
