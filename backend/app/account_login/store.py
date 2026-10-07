import uuid
from datetime import datetime, timedelta

from psycopg import Connection

from app.account_login.protocol import LoginError, SESSION_LIFETIME, session_is_active


class LoginStore:
    def __init__(self, connection: Connection) -> None:
        # Independent short transactions must commit before the remote exchange.
        if not connection.autocommit:
            raise ValueError("LoginStore requires an autocommit connection")
        self.connection = connection

    def rate_limit(self, bucket_key: str, now: datetime) -> None:
        bucket_start = now.replace(second=0, microsecond=0)
        with self.connection.cursor() as cursor:
            cursor.execute("DELETE FROM security_login_rate_limits WHERE bucket_start < %s", (now - timedelta(minutes=10),))
            cursor.execute("""
                INSERT INTO security_login_rate_limits (bucket_key, bucket_start, request_count)
                VALUES (%s, %s, 1)
                ON CONFLICT (bucket_key, bucket_start) DO UPDATE
                SET request_count = security_login_rate_limits.request_count + 1
                WHERE security_login_rate_limits.request_count < 20
                RETURNING request_count
            """, (bucket_key, bucket_start))
            if cursor.fetchone() is None:
                raise LoginError(429, "rate_limited", "ログイン操作が多いため、少し待ってからお試しください。")

    @staticmethod
    def _cancel(cursor, browser_hash: str | None, now: datetime) -> list[uuid.UUID]:
        if browser_hash is None:
            return []
        cursor.execute("""
            UPDATE security_login_attempts
            SET status = 'cancelled', finished_at = %s
            WHERE browser_token_hash = %s AND status IN ('pending', 'exchanging')
            RETURNING id
        """, (now, browser_hash))
        return [row["id"] for row in cursor.fetchall()]

    def create_attempt(self, attempt: dict, previous_browser_hash: str | None) -> list[uuid.UUID]:
        with self.connection.transaction(), self.connection.cursor() as cursor:
            cursor.execute("DELETE FROM security_login_attempts WHERE expires_at < %s", (attempt["created_at"] - timedelta(days=1),))
            old_ids = self._cancel(cursor, previous_browser_hash, attempt["created_at"])
            cursor.execute("""
                INSERT INTO security_login_attempts
                (id, state_hash, browser_token_hash, pkce_challenge, created_at, expires_at)
                VALUES (%(id)s, %(state_hash)s, %(browser_token_hash)s, %(pkce_challenge)s, %(created_at)s, %(expires_at)s)
            """, attempt)
            return old_ids

    def claim_attempt(self, state_hash: str, browser_hash: str, now: datetime, cancelled: bool = False) -> dict:
        with self.connection.transaction(), self.connection.cursor() as cursor:
            cursor.execute("SELECT * FROM security_login_attempts WHERE state_hash = %s FOR UPDATE", (state_hash,))
            row = cursor.fetchone()
            if row is None or row["browser_token_hash"] != browser_hash:
                raise LoginError(403, "invalid_state", "ログインを開始したブラウザを確認できません。")
            if row["created_at"] > now or row["expires_at"] <= now:
                raise LoginError(410, "login_expired", "ログインの開始情報が期限切れです。もう一度お試しください。")
            if row["status"] != "pending" or row["consumed_at"] is not None:
                raise LoginError(409, "login_already_used", "このログイン情報はすでに使用されています。")
            cursor.execute("""
                UPDATE security_login_attempts SET status = %s, consumed_at = %s, finished_at = %s
                WHERE id = %s
            """, ("cancelled" if cancelled else "exchanging", now, now if cancelled else None, row["id"]))
            return row

    def fail_attempt(self, attempt_id: uuid.UUID, code: str, now: datetime) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute("""
                UPDATE security_login_attempts SET status = 'failed', finished_at = %s, last_error_code = %s
                WHERE id = %s AND status = 'exchanging'
            """, (now, code, attempt_id))

    def finish_login(self, attempt_id: uuid.UUID, issuer: str, subject: uuid.UUID,
                     login_id: uuid.UUID, token_hash: str, previous_token_hash: str | None,
                     now: datetime) -> dict:
        with self.connection.transaction(), self.connection.cursor() as cursor:
            cursor.execute("SELECT * FROM security_login_attempts WHERE id = %s FOR UPDATE", (attempt_id,))
            attempt = cursor.fetchone()
            if attempt is None or attempt["status"] != "exchanging" or attempt["expires_at"] <= now:
                raise LoginError(410, "login_expired", "ログインをやり直してください。")
            cursor.execute("""
                INSERT INTO security_accounts (id, issuer, subject, created_at, last_login_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (issuer, subject) DO UPDATE SET last_login_at = EXCLUDED.last_login_at
                RETURNING id, disabled_at
            """, (uuid.uuid4(), issuer, subject, now, now))
            account = cursor.fetchone()
            if account["disabled_at"] is not None:
                raise LoginError(403, "account_disabled", "このアカウントではSecurityを利用できません。")
            if previous_token_hash is not None:
                cursor.execute("UPDATE security_account_sessions SET revoked_at = %s WHERE token_hash = %s AND revoked_at IS NULL", (now, previous_token_hash))
            cursor.execute("""
                INSERT INTO security_account_sessions
                (id, account_id, login_id, token_hash, created_at, expires_at, last_seen_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (uuid.uuid4(), account["id"], login_id, token_hash, now, now + SESSION_LIFETIME, now))
            cursor.execute("UPDATE security_login_attempts SET status = 'completed', finished_at = %s WHERE id = %s", (now, attempt_id))
            return {"account_id": account["id"], "expires_at": now + SESSION_LIFETIME}

    def session(self, token_hash: str, issuer: str, now: datetime, touch: bool = False) -> dict | None:
        with self.connection.transaction(), self.connection.cursor() as cursor:
            cursor.execute("""
                SELECT s.*, a.disabled_at FROM security_account_sessions s
                JOIN security_accounts a ON a.id = s.account_id
                WHERE s.token_hash = %s AND a.issuer = %s FOR UPDATE OF s
            """, (token_hash, issuer))
            row = cursor.fetchone()
            if row is None or not session_is_active(row, now):
                return None
            if touch:
                cursor.execute("UPDATE security_account_sessions SET last_seen_at = %s WHERE id = %s", (now, row["id"]))
                row["last_seen_at"] = now
            return row

    def logout(self, token_hash: str | None, browser_hash: str | None, now: datetime) -> list[uuid.UUID]:
        with self.connection.transaction(), self.connection.cursor() as cursor:
            if token_hash is not None:
                cursor.execute("UPDATE security_account_sessions SET revoked_at = %s WHERE token_hash = %s AND revoked_at IS NULL", (now, token_hash))
            return self._cancel(cursor, browser_hash, now)
