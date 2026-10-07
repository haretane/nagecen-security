import { diagnosticRequest } from './client.mjs'

export function createPreparationClient({ apiBase, fetchImpl = globalThis.fetch, onSessionExpired }) {
  async function request(path, body, signal) {
    const response = await diagnosticRequest(fetchImpl, true, onSessionExpired,
      `${apiBase.replace(/\/$/, '')}${path}`, {
        method: body === undefined ? 'GET' : 'POST', headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error',
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(30_000)]) : AbortSignal.timeout(30_000),
      })
    if (!response.headers.get('content-type')?.toLowerCase().startsWith('application/json')) throw new Error('invalid_response')
    const raw = await response.text()
    if (raw.length > (path.startsWith('/api/scan-jobs') ? 4_194_304 : 16_384)) throw new Error('invalid_response')
    const data = JSON.parse(raw)
    if (!response.ok) {
      const error = new Error('診断の準備を完了できませんでした。')
      error.code = typeof data.detail?.code === 'string' ? data.detail.code : 'request_failed'
      error.status = response.status
      throw error
    }
    if (path === '/api/url-validation' && (data?.valid !== true || typeof data.normalized_url !== 'string')) throw new Error('invalid_response')
    if (path === '/api/site-verifications' && (!/^[0-9a-f-]{36}$/.test(data?.verification_id ?? '')
      || typeof data.token !== 'string' || typeof data.meta_tag !== 'string'
      || typeof data.target_url !== 'string' || !Number.isFinite(Date.parse(data.expires_at)))) throw new Error('invalid_response')
    if (path.startsWith('/api/scan-jobs') && (!/^[0-9a-f-]{36}$/.test(data?.id ?? '')
      || !['queued', 'running', 'completed', 'failed', 'cancelled'].includes(data.status)
      || typeof data.target_url !== 'string' || !Array.isArray(data.findings))) throw new Error('invalid_response')
    return data
  }
  return {
    validate: (url, signal) => request('/api/url-validation', { url }, signal),
    issue: (url, signal) => request('/api/site-verifications', { url }, signal),
    confirm: (tag, signal) => request(`/api/site-verifications/${encodeURIComponent(tag.verification_id)}/confirm`, { token: tag.token }, signal),
    start: (body, signal) => request('/api/scan-jobs', body, signal),
    job: (id, signal) => request(`/api/scan-jobs/${encodeURIComponent(id)}`, undefined, signal),
    cancel: (id, signal) => request(`/api/scan-jobs/${encodeURIComponent(id)}/cancel`, {}, signal),
  }
}
