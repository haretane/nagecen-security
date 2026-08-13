import ipaddress
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit


Resolver = Callable[[str, int], Iterable[str]]

ALLOWED_SCHEMES = {"http": 80, "https": 443}
MAX_URL_LENGTH = 2_048


@dataclass(frozen=True)
class ValidatedUrl:
    normalized_url: str
    scheme: str
    hostname: str
    port: int
    resolved_ips: tuple[str, ...]


class UrlValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def resolve_hostname(hostname: str, port: int) -> set[str]:
    """ホスト名を、接続に使われる可能性があるIPアドレスへ変換します。"""

    try:
        address_info = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as error:
        raise UrlValidationError(
            "dns_resolution_failed",
            "ホスト名から接続先を確認できませんでした。URLをご確認ください。",
        ) from error

    return {item[4][0] for item in address_info}


def _normalize_hostname(hostname: str) -> str:
    normalized = hostname.rstrip(".").lower()

    if not normalized:
        raise UrlValidationError("missing_hostname", "ホスト名を入力してください。")

    try:
        return normalized.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise UrlValidationError(
            "invalid_hostname",
            "ホスト名の形式が正しくありません。",
        ) from error


def _require_public_ip(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as error:
        raise UrlValidationError(
            "invalid_ip_address",
            "接続先IPアドレスを確認できませんでした。",
        ) from error

    if not parsed_address.is_global:
        raise UrlValidationError(
            "private_network_address",
            "ローカル環境や内部ネットワークのURLは診断できません。",
        )

    return parsed_address


def _build_normalized_url(parsed: SplitResult, hostname: str, port: int) -> str:
    scheme = parsed.scheme.lower()
    default_port = ALLOWED_SCHEMES[scheme]
    host_for_url = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host_for_url if port == default_port else f"{host_for_url}:{port}"
    path = parsed.path or "/"

    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def validate_public_url(
    raw_url: str,
    resolver: Resolver = resolve_hostname,
) -> ValidatedUrl:
    """診断候補URLが公開Webサイトを指していることを検証します。

    この関数はURLの安全性を判定するだけで、対象サイトへHTTPアクセスはしません。
    """

    if not raw_url or not raw_url.strip():
        raise UrlValidationError("empty_url", "診断するURLを入力してください。")

    if raw_url != raw_url.strip() or any(character.isspace() for character in raw_url):
        raise UrlValidationError(
            "invalid_whitespace",
            "URLに空白や改行を含めることはできません。",
        )

    if len(raw_url) > MAX_URL_LENGTH:
        raise UrlValidationError("url_too_long", "URLが長すぎます。")

    if "\\" in raw_url:
        raise UrlValidationError(
            "invalid_character",
            "URLに使用できない文字が含まれています。",
        )

    try:
        parsed = urlsplit(raw_url)
        port = parsed.port
    except ValueError as error:
        raise UrlValidationError("invalid_url", "URLの形式が正しくありません。") from error

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlValidationError(
            "unsupported_scheme",
            "URLは http:// または https:// で始めてください。",
        )

    if parsed.username is not None or parsed.password is not None:
        raise UrlValidationError(
            "credentials_in_url",
            "IDやパスワードを含むURLは使用できません。",
        )

    if parsed.fragment:
        raise UrlValidationError(
            "fragment_not_allowed",
            "#以降を除いたURLを入力してください。",
        )

    if parsed.hostname is None:
        raise UrlValidationError("missing_hostname", "ホスト名を入力してください。")

    hostname = _normalize_hostname(parsed.hostname)
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise UrlValidationError(
            "localhost_not_allowed",
            "localhostは診断できません。",
        )

    expected_port = ALLOWED_SCHEMES[scheme]
    actual_port = port or expected_port
    if actual_port != expected_port:
        raise UrlValidationError(
            "port_not_allowed",
            f"{scheme}ではポート{expected_port}だけ使用できます。",
        )

    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        resolved_addresses = set(resolver(hostname, actual_port))
    else:
        resolved_addresses = {str(literal_ip)}

    if not resolved_addresses:
        raise UrlValidationError(
            "dns_resolution_failed",
            "接続先IPアドレスを確認できませんでした。",
        )

    public_addresses = sorted(
        str(_require_public_ip(address)) for address in resolved_addresses
    )
    normalized_url = _build_normalized_url(parsed, hostname, actual_port)

    return ValidatedUrl(
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        port=actual_port,
        resolved_ips=tuple(public_addresses),
    )
