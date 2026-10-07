import os
from contextlib import asynccontextmanager

import psycopg
from fastapi import FastAPI, HTTPException, Request
from urllib.parse import urlsplit
from app.scans.catalogue_edits import CatalogueEdit, read_edits, save_edit
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.security.diagnostic_availability import diagnostics_paused, blocks_diagnostic_request

from app.api.routes.url_validation import router as url_validation_router
from app.api.routes.site_verification import router as site_verification_router
from app.api.routes.scan_jobs import router as scan_jobs_router
from app.integrations.nagecen import router as nagecen_integration_router
from app.security.runtime_config import validate_production_config
from app.account_login.routes import router as account_login_router


def get_allowed_origins() -> list[str]:
    configured_origins = os.getenv(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:5174,http://localhost:5173",
    )
    return [origin.strip() for origin in configured_origins.split(",") if origin.strip()]


@asynccontextmanager
async def lifespan(_app: FastAPI):
    validate_production_config(component="backend")
    yield


app = FastAPI(
    title="NAGeCen Security API",
    description="NAGeCen SecurityのバックエンドAPIです。",
    version="0.1.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def submission_diagnostic_gate(request: Request, call_next):
    if diagnostics_paused() and blocks_diagnostic_request(request.method, request.url.path):
        return JSONResponse(status_code=503, content={"detail": {
            "code": "diagnostics_paused",
            "message": "利用条件を確認するため、診断機能を一時停止しています。プレビューモードをご利用ください。",
        }})
    return await call_next(request)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

app.include_router(url_validation_router)
app.include_router(site_verification_router)
app.include_router(scan_jobs_router)
app.include_router(nagecen_integration_router)
app.include_router(account_login_router)


@app.get("/api/development/finding-catalogue", include_in_schema=False)
def finding_catalogue() -> dict:
    if os.getenv("APP_ENV", "production") != "development":
        raise HTTPException(status_code=404, detail="Not found")
    from app.scans.result_presenter import (
        FRIENDLY_FINDINGS_BY_NAME, IMPROVEMENT_FINDING_NAMES,
        REFERENCE_FINDING_NAMES, build_finding_ai_prompt,
    )
    names = sorted(set(FRIENDLY_FINDINGS_BY_NAME) | IMPROVEMENT_FINDING_NAMES |
                   REFERENCE_FINDING_NAMES | {
                       "Strict-Transport-Security Header Not Set",
                       "Information Disclosure - Suspicious Comments",
                   })
    items = []
    for name in names:
        friendly = FRIENDLY_FINDINGS_BY_NAME.get(name)
        finding = {
            "technical_title": name,
            "title": friendly[0] if friendly else name,
            "description": friendly[1] if friendly else "未収録：実際の診断ではZAPの原文を表示します。",
            "solution": friendly[2] if friendly else "未収録：実際の診断ではZAPの対処案を表示します。",
            "locations": [], "location_count": "診断時に差し込み",
            "risk_label": "診断時に差し込み", "priority_label": "診断時に差し込み",
        }
        items.append({
            "name": name, "mapped": friendly is not None,
            "title": friendly[0] if friendly else None,
            "description": friendly[1] if friendly else None,
            "solution": friendly[2] if friendly else None,
            "group": "参考情報" if name in REFERENCE_FINDING_NAMES else
                     "改善候補" if name in IMPROVEMENT_FINDING_NAMES else "要注意の改善点",
            "prompt": build_finding_ai_prompt(finding),
        })
    from app.scans.zap_inventory import inventory
    edits = read_edits()
    for item in items:
        item['edit'] = edits.get(item['name'])
    return {"items": items, "inventory": inventory()}


@app.post('/api/development/finding-catalogue', include_in_schema=False)
def update_finding_catalogue(edit: CatalogueEdit, request: Request) -> dict:
    if os.getenv('APP_ENV', 'production') != 'development':
        raise HTTPException(404, detail='Not found')
    # Browser writes are accepted only from the configured local development UI.
    origin = request.headers.get('origin', '')
    try:
        parsed = urlsplit(origin)
        allowed = origin in get_allowed_origins() and parsed.hostname in {'localhost', '127.0.0.1'} and parsed.scheme == 'http'
    except ValueError:
        allowed = False
    if not allowed:
        raise HTTPException(403, detail='ローカル開発画面からのみ保存できます。')
    if edit.name not in {item['name'] for item in finding_catalogue()['items']}:
        raise HTTPException(422, detail='未登録の診断項目です。')
    return {'edit': save_edit(edit)}


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
