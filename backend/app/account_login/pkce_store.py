import uuid

from redis import Redis

from app.account_login.protocol import ATTEMPT_LIFETIME


class PkceStore:
    """Verifier lives only in non-persistent Redis with a ten-minute TTL."""

    def __init__(self, client: Redis) -> None:
        self.client = client

    @staticmethod
    def key(attempt_id: uuid.UUID) -> str:
        return f"account-login-pkce:{attempt_id}"

    def put(self, attempt_id: uuid.UUID, verifier: str) -> None:
        self.client.set(self.key(attempt_id), verifier, ex=int(ATTEMPT_LIFETIME.total_seconds()))

    def take(self, attempt_id: uuid.UUID) -> str | None:
        return self.client.getdel(self.key(attempt_id))

    def delete(self, attempt_id: uuid.UUID) -> None:
        self.client.delete(self.key(attempt_id))
