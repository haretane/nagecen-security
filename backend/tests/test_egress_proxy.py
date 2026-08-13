import asyncio

from app.worker.egress_proxy import RestrictedEgressProxy


async def _request_through_proxy(request: bytes) -> bytes:
    proxy = RestrictedEgressProxy("example.com")
    server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(request)
        await writer.drain()
        response = await reader.read(1024)
        writer.close()
        await writer.wait_closed()
        return response
    finally:
        server.close()
        await server.wait_closed()


def test_proxy_rejects_private_ip_connect() -> None:
    response = asyncio.run(
        _request_through_proxy(
            b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"
        )
    )

    assert response.startswith(b"HTTP/1.1 403 Forbidden")


def test_proxy_rejects_unapproved_hostname() -> None:
    response = asyncio.run(
        _request_through_proxy(
            b"CONNECT other.example:443 HTTP/1.1\r\nHost: other.example:443\r\n\r\n"
        )
    )

    assert response.startswith(b"HTTP/1.1 403 Forbidden")
