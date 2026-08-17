from collections.abc import Mapping
from copy import deepcopy
import re

from app.security.url_scope import UrlScope, path_is_in_scope


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


def keep_report_in_scope(report: Mapping, scope: UrlScope) -> dict:
    filtered = deepcopy(dict(report))
    sites = filtered.get("site", [])
    if not isinstance(sites, list):
        filtered["site"] = []
        return filtered

    for site in sites:
        if not isinstance(site, dict):
            continue
        kept_alerts = []
        for alert in site.get("alerts", []):
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances", [])
            kept_instances = [
                instance
                for instance in instances
                if isinstance(instance, dict)
                and isinstance(instance.get("uri"), str)
                and path_is_in_scope(instance["uri"], scope)
            ]
            if kept_instances:
                alert["instances"] = kept_instances
                alert["count"] = str(len(kept_instances))
                kept_alerts.append(alert)
        site["alerts"] = kept_alerts
    return filtered
