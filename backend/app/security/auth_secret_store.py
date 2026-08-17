import json
import os
import uuid
from dataclasses import asdict, dataclass

from redis import Redis


AUTH_SECRET_TTL_SECONDS = 15 * 60
AUTH_SECRET_KEY_PREFIX = "scan-auth:"


@dataclass(frozen=True)
class FormAuthenticationSecret:
    login_url: str
    identifier: str
    password: str


class AuthenticationSecretStore:
    """Short-lived, single-use storage for credentials that must never enter PostgreSQL."""

    def __init__(self, client: Redis, ttl_seconds: int = AUTH_SECRET_TTL_SECONDS) -> None:
        self._client = client
        self._ttl_seconds = ttl_seconds

    @staticmethod
    def _key(job_id: uuid.UUID) -> str:
        return f"{AUTH_SECRET_KEY_PREFIX}{job_id}"

    def put(self, job_id: uuid.UUID, secret: FormAuthenticationSecret) -> None:
        self._client.set(
            self._key(job_id),
            json.dumps(asdict(secret), ensure_ascii=False),
            ex=self._ttl_seconds,
        )

    def take(self, job_id: uuid.UUID) -> FormAuthenticationSecret | None:
        payload = self._client.getdel(self._key(job_id))
        if payload is None:
            return None
        values = json.loads(payload)
        return FormAuthenticationSecret(**values)

    def delete(self, job_id: uuid.UUID) -> None:
        self._client.delete(self._key(job_id))


def create_authentication_secret_store() -> AuthenticationSecretStore:
    client = Redis.from_url(
        os.environ["AUTH_SECRET_STORE_URL"],
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
    )
    return AuthenticationSecretStore(client)
