from app.main import get_allowed_origins


def test_default_cors_origins_include_both_frontends(monkeypatch) -> None:
    monkeypatch.delenv("CORS_ALLOWED_ORIGINS", raising=False)

    assert get_allowed_origins() == [
        "http://localhost:5174",
        "http://localhost:5173",
    ]


def test_cors_origins_are_configurable(monkeypatch) -> None:
    monkeypatch.setenv(
        "CORS_ALLOWED_ORIGINS",
        "https://security.example.com, https://nagecen.example.com",
    )

    assert get_allowed_origins() == [
        "https://security.example.com",
        "https://nagecen.example.com",
    ]
