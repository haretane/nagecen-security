import pytest

from app.security.url_validator import UrlValidationError, validate_public_url


def public_resolver(_hostname: str, _port: int) -> set[str]:
    return {"93.184.216.34"}


@pytest.mark.parametrize(
    ("url", "expected_url"),
    [
        ("https://example.com", "https://example.com/"),
        ("https://EXAMPLE.com/path?q=1", "https://example.com/path?q=1"),
        ("http://example.com/page", "http://example.com/page"),
    ],
)
def test_accepts_public_web_urls(url: str, expected_url: str) -> None:
    result = validate_public_url(url, resolver=public_resolver)

    assert result.normalized_url == expected_url
    assert result.resolved_ips == ("93.184.216.34",)


@pytest.mark.parametrize(
    ("url", "expected_code"),
    [
        ("ftp://example.com", "unsupported_scheme"),
        ("https://user:password@example.com", "credentials_in_url"),
        ("https://example.com:8443", "port_not_allowed"),
        ("https://example.com/#settings", "fragment_not_allowed"),
        ("https://example.com\\@127.0.0.1", "invalid_character"),
        (" https://example.com", "invalid_whitespace"),
        ("https://localhost", "localhost_not_allowed"),
        ("https://app.localhost", "localhost_not_allowed"),
        ("https://127.0.0.1", "private_network_address"),
        ("https://10.0.0.1", "private_network_address"),
        ("https://172.16.0.1", "private_network_address"),
        ("https://192.168.1.1", "private_network_address"),
        ("https://169.254.169.254", "private_network_address"),
        ("https://[::1]", "private_network_address"),
    ],
)
def test_rejects_unsafe_urls(url: str, expected_code: str) -> None:
    with pytest.raises(UrlValidationError) as captured:
        validate_public_url(url, resolver=public_resolver)

    assert captured.value.code == expected_code


def test_rejects_hostname_when_any_resolved_ip_is_private() -> None:
    def mixed_resolver(_hostname: str, _port: int) -> set[str]:
        return {"93.184.216.34", "10.0.0.10"}

    with pytest.raises(UrlValidationError) as captured:
        validate_public_url("https://example.com", resolver=mixed_resolver)

    assert captured.value.code == "private_network_address"
