// No secrets, account passwords, or login state are stored in browser storage.
const TOKEN = /^[A-Za-z0-9_-]{43}$/
const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const CALLBACK_PATH = '/auth/nagecen/callback'
const ERRORS = {
  login_required: 'NAGeCenアカウントで、もう一度ログインしてください。',
  login_expired: 'ログインの有効期限が切れました。最初からやり直してください。',
  invalid_state: 'ログインを開始したブラウザを確認できません。最初からやり直してください。',
  invalid_grant: 'ログイン情報が期限切れか、使用済みです。最初からやり直してください。',
  invalid_callback: 'ログインの戻り情報を確認できません。最初からやり直してください。',
  csrf_failed: 'Securityの画面から、もう一度操作してください。',
  login_rate_limited: 'ログインの操作が続いています。少し待ってからお試しください。',
  login_unavailable: 'ログイン連携の準備が整っていないか、接続できません。時間をおいてお試しください。',
  invalid_response: 'ログインの応答を確認できません。最初からやり直してください。',
  network_error: '接続を確認できませんでした。時間をおいてお試しください。',
}

export class AccountLoginError extends Error {
  constructor(code) {
    const safeCode = Object.hasOwn(ERRORS, code) ? code : 'login_unavailable'
    super(ERRORS[safeCode])
    this.code = safeCode
  }
}

export function captureCallback(location, history) {
  if (location.pathname !== CALLBACK_PATH) return null
  const search = location.search
  // Remove credentials even when login is disabled or the query is invalid.
  history.replaceState(null, '', CALLBACK_PATH)
  if (search.length > 2048) return { invalid: true }
  const params = new URLSearchParams(search)
  const keys = [...params.keys()].sort()
  const isCode = keys.join(',') === 'code,state'
  const isCancel = keys.join(',') === 'error,state'
  const state = params.get('state')
  if ((!isCode && !isCancel) || !TOKEN.test(state ?? '')) return { invalid: true }
  if (isCode && TOKEN.test(params.get('code') ?? '')) return { state, code: params.get('code') }
  if (isCancel && params.get('error') === 'access_denied') return { state, error: 'access_denied' }
  return { invalid: true }
}

export function validateAuthorizationUrl(value, expectedBase) {
  try {
    if (typeof value !== 'string' || value.length > 2048 || /[\s\\]/.test(value)) throw new Error()
    const url = new URL(value)
    const base = new URL(expectedBase)
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== base.origin
      || url.pathname !== base.pathname || url.username || url.password || url.hash
      || base.search || base.hash || base.username || base.password) throw new Error()
    const keys = [...url.searchParams.keys()].sort().join(',')
    if (keys !== 'client_id,code_challenge,code_challenge_method,state'
      || url.searchParams.get('client_id') !== 'nagecen-security'
      || url.searchParams.get('code_challenge_method') !== 'S256'
      || !TOKEN.test(url.searchParams.get('state') ?? '')
      || !TOKEN.test(url.searchParams.get('code_challenge') ?? '')) throw new Error()
    return url.href
  } catch {
    throw new AccountLoginError('invalid_response')
  }
}

export function validateSession(value, now = Date.now()) {
  if (value?.authenticated === false && Object.keys(value).length === 1) return value
  if (value?.authenticated !== true || Object.keys(value).sort().join(',') !== 'account_id,authenticated,expires_at'
    || !UUID4.test(value.account_id ?? '') || typeof value.expires_at !== 'string'
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/.test(value.expires_at)
    || !Number.isFinite(Date.parse(value.expires_at))) throw new AccountLoginError('invalid_response')
  if (Date.parse(value.expires_at) <= now) return { authenticated: false }
  return value
}

export function createAccountClient({ apiBase = 'http://localhost:8000',
  authorizationBase = 'http://localhost:5173/nagecen/security-login', fetcher = globalThis.fetch } = {}) {
  async function request(path, { method = 'GET', payload, signal } = {}) {
    try {
      const response = await fetcher(`${apiBase}${path}`, {
        method, credentials: 'include', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer',
        headers: method === 'POST' ? { 'Content-Type': 'application/json' } : undefined,
        body: method === 'POST' ? JSON.stringify(payload) : undefined,
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(8000)]) : AbortSignal.timeout(8000),
      })
      if (!response.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
        throw new AccountLoginError('invalid_response')
      }
      const raw = await response.text()
      if (raw.length > 8192) throw new AccountLoginError('invalid_response')
      let data
      try { data = JSON.parse(raw) } catch { throw new AccountLoginError('invalid_response') }
      if (!response.ok) throw new AccountLoginError(data?.code ?? data?.detail?.code)
      return data
    } catch (error) {
      if (signal?.aborted) throw error
      throw error instanceof AccountLoginError ? error : new AccountLoginError('network_error')
    }
  }
  return {
    async start() {
      const value = await request('/api/auth/nagecen/start', { method: 'POST', payload: {} })
      if (Object.keys(value ?? {}).join(',') !== 'authorization_url') throw new AccountLoginError('invalid_response')
      return validateAuthorizationUrl(value.authorization_url, authorizationBase)
    },
    async complete(payload) {
      const value = await request('/api/auth/nagecen/complete', { method: 'POST', payload })
      if (!value || Object.keys(value).sort().join(',') !== 'redirect_path,status'
        || !((value.status === 'success' && value.redirect_path === '/check')
          || (value.status === 'cancelled' && value.redirect_path === '/'))) throw new AccountLoginError('invalid_response')
      return value
    },
    async session(signal) { return validateSession(await request('/api/auth/session', { signal })) },
    async logout() {
      const value = await request('/api/auth/logout', { method: 'POST', payload: {} })
      if (value?.status !== 'success' || value.authenticated !== false
        || Object.keys(value).sort().join(',') !== 'authenticated,status') throw new AccountLoginError('invalid_response')
      return value
    },
  }
}

// Construct outside React. StrictMode's repeated effects share this one promise;
// neither network failures nor remounts automatically reuse the short-lived code.
export function createCallbackTask(initialPayload, client) {
  let payload = initialPayload
  let task
  return () => {
    if (!task) {
      task = (async () => {
        try {
          if (!payload || payload.invalid) throw new AccountLoginError('invalid_callback')
          const result = await client.complete(payload)
          if (result.status === 'success') {
            const session = await client.session()
            if (!session.authenticated) throw new AccountLoginError('login_required')
          }
          return result
        } finally {
          payload = null
        }
      })()
    }
    return task
  }
}

export async function diagnosticRequest(fetcher, accountMode, onExpired, url, options = {}) {
  const response = await fetcher(url, accountMode
    ? { ...options, credentials: 'include', cache: 'no-store', referrerPolicy: 'no-referrer' }
    : options)
  if (accountMode && response.status === 401) onExpired?.()
  return response
}
