import uuid

from app.security.auth_secret_store import (
    AuthenticationSecretStore,
    FormAuthenticationSecret,
)


class FakeRedis:
    def __init__(self) -> None:
        self.values = {}
        self.expirations = {}

    def set(self, key, value, ex):
        self.values[key] = value
        self.expirations[key] = ex

    def getdel(self, key):
        self.expirations.pop(key, None)
        return self.values.pop(key, None)

    def delete(self, key):
        self.expirations.pop(key, None)
        self.values.pop(key, None)


def test_authentication_secret_is_short_lived_and_single_use() -> None:
    client = FakeRedis()
    store = AuthenticationSecretStore(client, ttl_seconds=60)
    job_id = uuid.uuid4()
    secret = FormAuthenticationSecret(
        login_url="https://example.com/login",
        identifier="diagnosis-user@example.com",
        password="temporary-secret",
    )

    store.put(job_id, secret)

    assert client.expirations[f"scan-auth:{job_id}"] == 60
    assert store.take(job_id) == secret
    assert store.take(job_id) is None


def test_authentication_secret_can_be_explicitly_deleted() -> None:
    client = FakeRedis()
    store = AuthenticationSecretStore(client)
    job_id = uuid.uuid4()
    store.put(job_id, FormAuthenticationSecret("https://example.com/login", "user", "secret"))

    store.delete(job_id)

    assert store.take(job_id) is None
