import argparse
import asyncio
from contextlib import suppress
from urllib.parse import urlsplit

from app.security.url_validator import UrlValidationError, validate_public_url


MAX_HEADER_BYTES = 64 * 1024
CONNECT_TIMEOUT_SECONDS = 10


async def _relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(64 * 1024):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()


class RestrictedEgressProxy:
    def __init__(self, allowed_host: str) -> None:
        self.allowed_host = allowed_host.rstrip(".").lower().encode("idna").decode("ascii")

    async def _validated_connection(self, host: str, port: int):
        scheme = "https" if port == 443 else "http"
        validated = validate_public_url(f"{scheme}://{host}:{port}/")
        if validated.hostname != self.allowed_host:
            raise UrlValidationError("host_not_allowed", "This host is not allowed")

        last_error: OSError | None = None
        for address in validated.resolved_ips:
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(address, port),
                    timeout=CONNECT_TIMEOUT_SECONDS,
                )
            except OSError as error:
                last_error = error

        raise last_error or OSError("No public address available")

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            header = await reader.readuntil(b"\r\n\r\n")
            if len(header) > MAX_HEADER_BYTES:
                raise ValueError("Headers too large")

            first_line, *header_lines = header.decode("iso-8859-1").split("\r\n")
            method, target, version = first_line.split(" ", 2)

            if method.upper() == "CONNECT":
                host, separator, port_text = target.rpartition(":")
                if not separator or int(port_text) != 443:
                    raise ValueError("Only CONNECT port 443 is allowed")
                upstream_reader, upstream_writer = await self._validated_connection(host, 443)
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
            else:
                parsed = urlsplit(target)
                if parsed.scheme != "http" or parsed.hostname is None or (parsed.port or 80) != 80:
                    raise ValueError("Only absolute HTTP URLs on port 80 are allowed")
                upstream_reader, upstream_writer = await self._validated_connection(parsed.hostname, 80)
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                filtered_headers = [
                    line for line in header_lines
                    if line and not line.lower().startswith(("proxy-connection:", "proxy-authorization:"))
                ]
                forwarded = f"{method} {path} {version}\r\n" + "\r\n".join(filtered_headers) + "\r\n\r\n"
                upstream_writer.write(forwarded.encode("iso-8859-1"))
                await upstream_writer.drain()

            await asyncio.gather(
                _relay(reader, upstream_writer),
                _relay(upstream_reader, writer),
            )
        except (ValueError, OSError, asyncio.IncompleteReadError, UrlValidationError):
            if not writer.is_closing():
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                with suppress(Exception):
                    await writer.drain()
                writer.close()


async def serve(allowed_host: str, port: int) -> None:
    proxy = RestrictedEgressProxy(allowed_host)
    server = await asyncio.start_server(proxy.handle, "0.0.0.0", port)
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allowed-host", required=True)
    parser.add_argument("--port", type=int, default=8080)
    arguments = parser.parse_args()
    asyncio.run(serve(arguments.allowed_host, arguments.port))


if __name__ == "__main__":
    main()
