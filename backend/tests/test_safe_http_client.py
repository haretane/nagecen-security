import asyncio

import pytest

from app.security import safe_http_client
from app.security.url_validator import UrlValidationError, ValidatedUrl, validate_public_url
from app.security.url_scope import UrlScope


def fake_public_validation(url: str) -> ValidatedUrl:
    if "127.0.0.1" in url:
        return validate_public_url(url)

    path = "/verification" if url.endswith("/verification") else "/"
    return ValidatedUrl(
        normalized_url=f"https://example.com{path}",
        scheme="https",
        hostname="example.com",
        port=443,
        resolved_ips=("93.184.216.34",),
    )


def test_revalidates_redirect_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []

    async def fake_request(validated):
        requested_urls.append(validated.normalized_url)
        return 302, {"Location": "http://127.0.0.1/admin"}, b""

    monkeypatch.setattr(safe_http_client, "_request_once", fake_request)
    monkeypatch.setattr(safe_http_client, "validate_public_url", fake_public_validation)

    with pytest.raises(UrlValidationError) as captured:
        asyncio.run(safe_http_client.fetch_public_html("https://example.com"))

    assert captured.value.code == "private_network_address"
    assert requested_urls == ["https://example.com/"]


def test_accepts_html_after_safe_relative_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = iter(
        [
            (302, {"Location": "/verification"}, b""),
            (200, {"Content-Type": "text/html; charset=utf-8"}, b"<html></html>"),
        ]
    )

    async def fake_request(_validated):
        return next(responses)

    monkeypatch.setattr(safe_http_client, "_request_once", fake_request)
    monkeypatch.setattr(safe_http_client, "validate_public_url", fake_public_validation)

    response = asyncio.run(safe_http_client.fetch_public_html("https://example.com"))

    assert response.final_url == "https://example.com/verification"
    assert response.redirect_count == 1


def test_rejects_different_public_host_before_request(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []

    def fake_validation(url: str) -> ValidatedUrl:
        hostname = "other.example" if "other.example" in url else "example.com"
        return ValidatedUrl(
            normalized_url=f"https://{hostname}/",
            scheme="https",
            hostname=hostname,
            port=443,
            resolved_ips=("93.184.216.34",),
        )

    async def fake_request(validated):
        requested_urls.append(validated.normalized_url)
        return 302, {"Location": "https://other.example/"}, b""

    monkeypatch.setattr(safe_http_client, "validate_public_url", fake_validation)
    monkeypatch.setattr(safe_http_client, "_request_once", fake_request)

    with pytest.raises(safe_http_client.SafeHttpError) as captured:
        asyncio.run(
            safe_http_client.fetch_public_html(
                "https://example.com",
                allowed_host="example.com",
            )
        )

    assert captured.value.code == "host_changed"
    assert requested_urls == ["https://example.com/"]


def test_rejects_redirect_outside_product_path(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = iter(
        [(302, {"Location": "/app-a/"}, b"")]
    )

    async def fake_request(_validated):
        return next(responses)

    def scoped_validation(url: str) -> ValidatedUrl:
        path = "/app-a/" if url.endswith("/app-a/") else "/nagecen/"
        return ValidatedUrl(
            normalized_url=f"https://example.com{path}",
            scheme="https",
            hostname="example.com",
            port=443,
            resolved_ips=("93.184.216.34",),
        )

    monkeypatch.setattr(safe_http_client, "_request_once", fake_request)
    monkeypatch.setattr(safe_http_client, "validate_public_url", scoped_validation)

    with pytest.raises(safe_http_client.SafeHttpError) as captured:
        asyncio.run(
            safe_http_client.fetch_public_html(
                "https://example.com/nagecen/",
                allowed_scope=UrlScope("https://example.com", "/nagecen/"),
            )
        )

    assert captured.value.code == "scope_changed"


def test_rejects_oversized_html(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_request(_validated):
        return (
            200,
            {"Content-Type": "text/html"},
            b"x" * (safe_http_client.MAX_HTML_BYTES + 1),
        )

    monkeypatch.setattr(safe_http_client, "_request_once", fake_request)
    monkeypatch.setattr(safe_http_client, "validate_public_url", fake_public_validation)

    with pytest.raises(safe_http_client.SafeHttpError) as captured:
        asyncio.run(safe_http_client.fetch_public_html("https://example.com"))

    assert captured.value.code == "response_too_large"
