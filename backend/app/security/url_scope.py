from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit

from app.security.url_validator import ValidatedUrl


WEB_PAGE_EXTENSIONS = {".html", ".htm", ".php", ".asp", ".aspx", ".jsp"}


@dataclass(frozen=True)
class UrlScope:
    origin: str
    base_path: str


class UrlScopeError(ValueError):
    pass


def origin_from_validated_url(validated: ValidatedUrl) -> str:
    default_port = 443 if validated.scheme == "https" else 80
    host = f"[{validated.hostname}]" if ":" in validated.hostname else validated.hostname
    port_suffix = "" if validated.port == default_port else f":{validated.port}"
    return f"{validated.scheme}://{host}{port_suffix}"


def normalize_url_path(url: str) -> str:
    raw_path = urlsplit(url).path or "/"
    lowered_path = raw_path.lower()
    if "%2f" in lowered_path or "%5c" in lowered_path or "\\" in raw_path:
        raise UrlScopeError("URLのパスに使用できない区切り文字が含まれています。")

    decoded_path = unquote(raw_path)
    segments = decoded_path.split("/")
    if any(segment in {".", ".."} for segment in segments):
        raise UrlScopeError("URLのパスに相対移動を含めることはできません。")

    normalized_segments = [
        quote(segment, safe="!$&'()*+,;=:@-._~")
        for segment in segments
        if segment
    ]
    normalized = "/" + "/".join(normalized_segments)
    if raw_path.endswith("/") and normalized != "/":
        normalized += "/"
    return normalized


def derive_base_path(url: str) -> str:
    normalized_path = normalize_url_path(url)
    if normalized_path == "/" or normalized_path.endswith("/"):
        return normalized_path

    last_segment = normalized_path.rsplit("/", 1)[-1].lower()
    if any(last_segment.endswith(extension) for extension in WEB_PAGE_EXTENSIONS):
        parent = normalized_path.rsplit("/", 1)[0]
        return f"{parent}/" if parent else "/"
    return f"{normalized_path}/"


# Backwards-compatible name for code that needs to derive a product scope.
def normalize_base_path(url: str) -> str:
    return derive_base_path(url)


def scope_from_validated_url(validated: ValidatedUrl) -> UrlScope:
    return UrlScope(
        origin=origin_from_validated_url(validated),
        base_path=derive_base_path(validated.normalized_url),
    )


def path_is_in_scope(url: str, scope: UrlScope) -> bool:
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port
        candidate_path = normalize_url_path(url)
    except (UrlScopeError, ValueError):
        return False

    if scheme not in {"http", "https"} or not hostname:
        return False

    host = f"[{hostname}]" if ":" in hostname else hostname
    candidate_origin = f"{scheme}://{host}"
    if port is not None:
        default_port = 443 if scheme == "https" else 80
        if port != default_port:
            candidate_origin += f":{port}"

    if candidate_origin != scope.origin:
        return False

    if scope.base_path == "/":
        return True
    scope_root = scope.base_path.rstrip("/")
    return candidate_path == scope_root or candidate_path.startswith(scope.base_path)
