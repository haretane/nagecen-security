import os


def diagnostics_paused() -> bool:
    # Fail closed for the submission; never enables real scanning implicitly.
    return os.getenv("SECURITY_DIAGNOSTICS_PAUSED", "true").lower() != "false"


def blocks_diagnostic_request(method: str, path: str) -> bool:
    if method != "POST":
        return False
    path = path.rstrip("/")
    return (path == "/api/url-validation"
            or path == "/api/site-verifications"
            or (path.startswith("/api/site-verifications/") and path.endswith("/confirm"))
            or path == "/api/scan-jobs"
            or path in {"/api/integrations/nagecen/handoffs", "/api/integrations/nagecen/handoff-token/exchange"})
