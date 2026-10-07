import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.scans import catalogue_edits
from app.scans.catalogue_edits import CatalogueEdit, read_edits, save_edit
from app.main import update_finding_catalogue


@pytest.fixture
def store(monkeypatch, tmp_path):
    monkeypatch.setattr(catalogue_edits, 'STORE_PATH', tmp_path / 'edits.json')
    monkeypatch.setenv('APP_ENV', 'development')
    monkeypatch.setenv('CORS_ALLOWED_ORIGINS', 'http://localhost:5174')


def request(origin):
    return Request({'type': 'http', 'headers': [(b'origin', origin.encode())]})


def test_save_reload_and_conflict(store):
    edit = CatalogueEdit(name='SQL Injection', title='日本語の下書き', status='draft')
    result = update_finding_catalogue(edit, request('http://localhost:5174'))
    assert result['edit']['revision'] == 1
    assert read_edits()['SQL Injection']['title'] == '日本語の下書き'
    with pytest.raises(HTTPException) as error:
        save_edit(edit)
    assert error.value.status_code == 409
    assert read_edits()['SQL Injection']['revision'] == 1


def test_external_origin_and_unknown_name_rejected(store):
    with pytest.raises(HTTPException) as error:
        update_finding_catalogue(CatalogueEdit(name='SQL Injection'), request('https://example.com'))
    assert error.value.status_code == 403
    with pytest.raises(HTTPException) as error:
        update_finding_catalogue(CatalogueEdit(name='../invalid'), request('http://localhost:5174'))
    assert error.value.status_code == 422
    assert not catalogue_edits.STORE_PATH.exists()


def test_production_write_disabled(store, monkeypatch):
    monkeypatch.setenv('APP_ENV', 'production')
    with pytest.raises(HTTPException) as error:
        update_finding_catalogue(CatalogueEdit(name='SQL Injection'), request('http://localhost:5174'))
    assert error.value.status_code == 404
    assert not catalogue_edits.STORE_PATH.exists()


def test_corrupt_store_not_overwritten(store):
    catalogue_edits.STORE_PATH.write_text('invalid', encoding='utf-8')
    with pytest.raises(HTTPException) as error:
        save_edit(CatalogueEdit(name='SQL Injection'))
    assert error.value.status_code == 503
    assert catalogue_edits.STORE_PATH.read_text() == 'invalid'
