import pytest
import asyncio
from starlette.requests import Request
from app.main import submission_diagnostic_gate
from app.security.diagnostic_availability import diagnostics_paused, blocks_diagnostic_request


def test_submission_defaults_to_paused(monkeypatch):
    monkeypatch.delenv('SECURITY_DIAGNOSTICS_PAUSED', raising=False)
    assert diagnostics_paused()
    monkeypatch.setenv('SECURITY_DIAGNOSTICS_PAUSED', 'false')
    assert not diagnostics_paused()


@pytest.mark.parametrize('path', ['/api/url-validation', '/api/site-verifications',
    '/api/site-verifications/fake/confirm', '/api/scan-jobs',
    '/api/integrations/nagecen/handoffs', '/api/integrations/nagecen/handoff-token/exchange'])
def test_paused_requests_rejected_before_database_or_network(monkeypatch, path):
    monkeypatch.setenv('SECURITY_DIAGNOSTICS_PAUSED', 'true')
    async def forbidden_next(_request):
        raise AssertionError('Paused request must not reach database or network handlers')
    request = Request({'type': 'http', 'method': 'POST', 'path': path, 'headers': []})
    result = asyncio.run(submission_diagnostic_gate(request, forbidden_next))
    assert result.status_code == 503
    assert b'diagnostics_paused' in result.body


def test_auth_health_and_cancellation_are_not_blocked():
    assert not blocks_diagnostic_request('POST', '/api/auth/logout')
    assert not blocks_diagnostic_request('GET', '/health')
    assert not blocks_diagnostic_request('POST', '/api/scan-jobs/id/cancel')
    assert not blocks_diagnostic_request('OPTIONS', '/api/scan-jobs')
