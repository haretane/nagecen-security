import asyncio
import socket
from dataclasses import dataclass
from urllib.parse import urljoin

import aiohttp
from aiohttp.abc import AbstractResolver

from app.security.url_validator import ValidatedUrl, validate_public_url


MAX_REDIRECTS = 5
MAX_HTML_BYTES = 1_000_000
REQUEST_TIMEOUT_SECONDS = 10


class SafeHttpError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class SafeHttpResponse:
    final_url: str
    status: int
    content_type: str
    body: bytes
    redirect_count: int


class PinnedResolver(AbstractResolver):
    """検証済みIPだけをHTTPクライアントへ渡すDNS resolverです。"""

    def __init__(self, hostname: str, addresses: tuple[str, ...]) -> None:
        self.hostname = hostname
        self.addresses = addresses

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[dict[str, object]]:
        if host.rstrip(".").lower().encode("idna").decode("ascii") != self.hostname:
            raise OSError("Unexpected hostname")

        return [
            {
                "hostname": host,
                "host": address,
                "port": port,
                "family": socket.AF_INET6 if ":" in address else socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
            for address in self.addresses
        ]

    async def close(self) -> None:
        return None


async def _request_once(validated: ValidatedUrl) -> tuple[int, dict[str, str], bytes]:
    resolver = PinnedResolver(validated.hostname, validated.resolved_ips)
    connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False)
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get(
                validated.normalized_url,
                allow_redirects=False,
                headers={
                    "Accept": "text/html,application/xhtml+xml",
                    "User-Agent": "NAGeCen-Security-Verification/0.1",
                },
            ) as response:
                body = await response.content.read(MAX_HTML_BYTES + 1)
                return response.status, dict(response.headers), body
    except asyncio.TimeoutError as error:
        raise SafeHttpError(
            "request_timeout",
            "対象サイトから時間内に応答がありませんでした。",
        ) from error
    except (aiohttp.ClientError, OSError) as error:
        raise SafeHttpError(
            "request_failed",
            "対象サイトへ安全に接続できませんでした。",
        ) from error


async def fetch_public_html(url: str, allowed_host: str | None = None) -> SafeHttpResponse:
    """公開URLからHTMLを取得し、リダイレクト先も毎回検証します。"""

    current_url = url

    for redirect_count in range(MAX_REDIRECTS + 1):
        validated = validate_public_url(current_url)
        if allowed_host is not None and validated.hostname != allowed_host:
            raise SafeHttpError(
                "host_changed",
                "所有確認中に別のホストへ移動することはできません。",
            )
        status, headers, body = await _request_once(validated)

        if status in {301, 302, 303, 307, 308}:
            if redirect_count == MAX_REDIRECTS:
                raise SafeHttpError(
                    "too_many_redirects",
                    "リダイレクト回数が上限を超えました。",
                )

            location = headers.get("Location")
            if not location:
                raise SafeHttpError(
                    "invalid_redirect",
                    "移動先が不明なリダイレクトを受け取りました。",
                )

            current_url = urljoin(validated.normalized_url, location)
            continue

        if status < 200 or status >= 300:
            raise SafeHttpError(
                "unexpected_status",
                f"対象サイトからHTTP {status}が返されました。",
            )

        if len(body) > MAX_HTML_BYTES:
            raise SafeHttpError(
                "response_too_large",
                "対象ページのHTMLが確認可能なサイズを超えています。",
            )

        content_type = headers.get("Content-Type", "").split(";", 1)[0].lower()
        if content_type not in {"text/html", "application/xhtml+xml"}:
            raise SafeHttpError(
                "not_html",
                "対象URLからHTMLページを取得できませんでした。",
            )

        return SafeHttpResponse(
            final_url=validated.normalized_url,
            status=status,
            content_type=content_type,
            body=body,
            redirect_count=redirect_count,
        )

    raise SafeHttpError("too_many_redirects", "リダイレクト回数が上限を超えました。")
