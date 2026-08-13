import os
from collections.abc import Iterator

import psycopg
from psycopg import Connection
from psycopg.rows import dict_row


def get_connection() -> Iterator[Connection]:
    with psycopg.connect(os.environ["DATABASE_URL"], row_factory=dict_row) as connection:
        yield connection

