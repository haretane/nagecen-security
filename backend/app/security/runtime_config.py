import os


LOCAL_SECRET_MARKERS = ("local-development", "change-me", "replace_with")


def validate_production_config(
    environment: dict[str, str] | None = None,
    component: str = "all",
) -> None:
    values = os.environ if environment is None else environment
    if values.get("APP_ENV", "development").lower() != "production":
        return

    errors: list[str] = []
    secret_names = {
        "backend": ("NAGECEN_TO_SECURITY_HMAC_SECRET",),
        "worker": ("SECURITY_TO_NAGECEN_HMAC_SECRET",),
        "all": ("NAGECEN_TO_SECURITY_HMAC_SECRET", "SECURITY_TO_NAGECEN_HMAC_SECRET"),
    }[component]
    for name in secret_names:
        secret = values.get(name, "")
        if len(secret) < 32 or any(marker in secret.lower() for marker in LOCAL_SECRET_MARKERS):
            errors.append(f"{name} must use a production secret")

    if component in {"backend", "all"} and values.get("COOKIE_SECURE", "false").lower() != "true":
        errors.append("COOKIE_SECURE must be true")

    origins = values.get("CORS_ALLOWED_ORIGINS", "")
    if component in {"backend", "all"} and ("localhost" in origins or "127.0.0.1" in origins):
        errors.append("CORS_ALLOWED_ORIGINS must not contain local origins")

    url_names = {
        "backend": ("SECURITY_FRONTEND_URL", "NAGECEN_FRONTEND_URL"),
        "worker": ("NAGECEN_CALLBACK_URL",),
        "all": ("SECURITY_FRONTEND_URL", "NAGECEN_FRONTEND_URL", "NAGECEN_CALLBACK_URL"),
    }[component]
    for name in url_names:
        value = values.get(name, "")
        if value and not value.startswith("https://"):
            errors.append(f"{name} must use https")

    if errors:
        raise RuntimeError("Unsafe production configuration: " + "; ".join(errors))
