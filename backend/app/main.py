import os

import psycopg
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.url_validation import router as url_validation_router
from app.api.routes.site_verification import router as site_verification_router


def get_allowed_origins() -> list[str]:
    configured_origins = os.getenv(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:5174,http://localhost:5173",
    )
    return [origin.strip() for origin in configured_origins.split(",") if origin.strip()]


app = FastAPI(
    title="NAGeCen Security API",
    description="NAGeCen SecurityのバックエンドAPIです。",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

app.include_router(url_validation_router)
app.include_router(site_verification_router)


@app.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    """APIとデータベースが応答できることを確認します。"""

    database_url = os.environ["DATABASE_URL"]

    try:
        with psycopg.connect(database_url, connect_timeout=3) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
    except psycopg.Error as error:
        raise HTTPException(
            status_code=503,
            detail={"status": "degraded", "database": "disconnected"},
        ) from error

    return {"status": "ok", "database": "connected"}
