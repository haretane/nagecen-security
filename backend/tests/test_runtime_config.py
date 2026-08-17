import pytest

from app.security.runtime_config import validate_production_config


def production_environment() -> dict[str, str]:
    return {
        "APP_ENV": "production",
        "NAGECEN_TO_SECURITY_HMAC_SECRET": "a" * 40,
        "SECURITY_TO_NAGECEN_HMAC_SECRET": "b" * 40,
        "COOKIE_SECURE": "true",
        "CORS_ALLOWED_ORIGINS": "https://security.example.com,https://nagecen.example.com",
        "SECURITY_FRONTEND_URL": "https://security.example.com",
        "NAGECEN_FRONTEND_URL": "https://nagecen.example.com",
        "NAGECEN_CALLBACK_URL": "https://nagecen.example.com/api/security-callback",
    }


def test_development_allows_local_configuration() -> None:
    validate_production_config({"APP_ENV": "development"})


def test_safe_production_configuration_is_accepted() -> None:
    validate_production_config(production_environment())


def test_production_rejects_local_defaults() -> None:
    environment = production_environment()
    environment["COOKIE_SECURE"] = "false"
    environment["CORS_ALLOWED_ORIGINS"] = "http://localhost:5174"
    environment["NAGECEN_TO_SECURITY_HMAC_SECRET"] = "local-development-handoff-secret-change-me"

    with pytest.raises(RuntimeError) as error:
        validate_production_config(environment)

    assert "COOKIE_SECURE" in str(error.value)
    assert "CORS_ALLOWED_ORIGINS" in str(error.value)
    assert "NAGECEN_TO_SECURITY_HMAC_SECRET" in str(error.value)
