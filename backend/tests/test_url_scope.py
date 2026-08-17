import pytest

from app.security.url_scope import (
    UrlScope,
    UrlScopeError,
    path_is_in_scope,
    scope_from_validated_url,
    derive_base_path,
)
from app.security.url_validator import ValidatedUrl


def validated(url: str, path_url: str | None = None) -> ValidatedUrl:
    return ValidatedUrl(
        normalized_url=path_url or url,
        scheme="https",
        hostname="ucu4.sakura.ne.jp",
        port=443,
        resolved_ips=("203.0.113.10",),
    )


def test_builds_origin_and_base_path() -> None:
    scope = scope_from_validated_url(
        validated(
            "https://ucu4.sakura.ne.jp/nagecen/",
            "https://ucu4.sakura.ne.jp/nagecen/",
        )
    )

    assert scope == UrlScope("https://ucu4.sakura.ne.jp", "/nagecen/")


def test_scope_does_not_include_sibling_product() -> None:
    scope = UrlScope("https://ucu4.sakura.ne.jp", "/nagecen/")

    assert path_is_in_scope("https://ucu4.sakura.ne.jp/nagecen/login", scope)
    assert not path_is_in_scope("https://ucu4.sakura.ne.jp/app-a/", scope)
    assert not path_is_in_scope("https://ucu4.sakura.ne.jp/nagecen-malicious/", scope)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/", "/"),
        ("https://example.com/app/", "/app/"),
        ("https://example.com/app", "/app/"),
        ("https://example.com/app/index.html", "/app/"),
        ("https://example.com/app/index.php?id=10", "/app/"),
        ("https://example.com/app.v2/", "/app.v2/"),
    ],
)
def test_derives_product_base_path(url: str, expected: str) -> None:
    assert derive_base_path(url) == expected


def test_file_entry_point_scope_includes_sibling_pages() -> None:
    scope = UrlScope("https://example.com", "/app/")

    assert path_is_in_scope("https://example.com/app/index.html", scope)
    assert path_is_in_scope("https://example.com/app/login", scope)
    assert not path_is_in_scope("https://example.com/application/", scope)


def test_scope_rejects_other_origin() -> None:
    scope = UrlScope("https://ucu4.sakura.ne.jp", "/nagecen/")

    assert not path_is_in_scope("http://ucu4.sakura.ne.jp/nagecen/", scope)
    assert not path_is_in_scope("https://other.example/nagecen/", scope)


def test_scope_rejects_malformed_report_url_without_crashing() -> None:
    scope = UrlScope("https://example.com", "/app/")

    assert not path_is_in_scope("https://example.com:broken/app/", scope)
    assert not path_is_in_scope("not-a-url", scope)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/app%2fadmin/",
        "https://example.com/app/../admin/",
    ],
)
def test_rejects_ambiguous_paths(url: str) -> None:
    with pytest.raises(UrlScopeError):
        scope_from_validated_url(
            ValidatedUrl(url, "https", "example.com", 443, ("93.184.216.34",))
        )
