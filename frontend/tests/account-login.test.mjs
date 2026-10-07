import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  AccountLoginError, captureCallback, createAccountClient, createCallbackTask,
  diagnosticRequest, validateAuthorizationUrl, validateSession,
} from '../src/account-login/client.mjs'

const BASE = 'http://localhost:5173/nagecen/security-login'
const VALID_URL = `${BASE}?client_id=nagecen-security&state=${'A'.repeat(43)}&code_challenge=${'B'.repeat(43)}&code_challenge_method=S256`
const PAYLOAD = { state: 'A'.repeat(43), code: 'C'.repeat(43) }
const SESSION = { authenticated: true, account_id: 'e527baf7-1a41-4095-88c1-5e7838462255', expires_at: '2099-10-04T12:00:00.123456Z' }

function mockClient(responses) {
  const calls = []
  const client = createAccountClient({ fetcher: async (...args) => {
    calls.push(args)
    const next = responses.shift()
    assert.ok(next, 'Unexpected additional request')
    return new Response(JSON.stringify(next.body), { status: next.status ?? 200,
      headers: { 'Content-Type': next.type ?? 'application/json' } })
  } })
  return { client, calls }
}

test('callback clears code/state/hash and history state before parsing', () => {
  const calls = []
  const payload = captureCallback({ pathname: '/auth/nagecen/callback', search: `?code=${PAYLOAD.code}&state=${PAYLOAD.state}`, hash: '#secret' },
    { replaceState: (...args) => calls.push(args) })
  assert.deepEqual(calls, [[null, '', '/auth/nagecen/callback']])
  assert.deepEqual(payload, PAYLOAD)
})

test('other routes never read or clear a legacy handoff query', () => {
  assert.equal(captureCallback({ pathname: '/integrations/nagecen', search: '?token=legacy' },
    { replaceState: () => assert.fail() }), null)
})

for (const query of ['', '?state=short&code=short', `?state=${PAYLOAD.state}&code=${PAYLOAD.code}&code=${PAYLOAD.code}`,
  `?state=${PAYLOAD.state}&code=${PAYLOAD.code}&redirect_url=https://evil.example/`,
  `?state=${PAYLOAD.state}&error=access_denied&code=${PAYLOAD.code}`, `?state=${PAYLOAD.state}&error=unknown`, '?'.repeat(2049)]) {
  test(`invalid callback is cleaned and rejected (${query.length} chars)`, () => {
    let cleaned = false
    assert.deepEqual(captureCallback({ pathname: '/auth/nagecen/callback', search: query },
      { replaceState: () => { cleaned = true } }), { invalid: true })
    assert.equal(cleaned, true)
  })
}

test('callback cancellation uses only the agreed fields', () => {
  assert.deepEqual(captureCallback({ pathname: '/auth/nagecen/callback', search: `?state=${PAYLOAD.state}&error=access_denied` },
    { replaceState() {} }), { state: PAYLOAD.state, error: 'access_denied' })
})

test('fixed main-app authorization URL is accepted', () => {
  assert.equal(validateAuthorizationUrl(VALID_URL, BASE), VALID_URL)
})

for (const value of [undefined, 'javascript:alert(1)', VALID_URL.replace('localhost:', 'evil.example:'),
  VALID_URL.replace('/security-login', '/another-path'), `${VALID_URL}#secret`, `${VALID_URL}&state=${PAYLOAD.state}`,
  `${VALID_URL}&return_url=https://evil.example`, VALID_URL.replace('S256', 'plain'), VALID_URL.replace('nagecen-security', 'other'),
  VALID_URL.replace('http://', 'http://name:password@'), `${VALID_URL}\n`]) {
  test('unknown authority/fields/credentials are not followed', () => {
    assert.throws(() => validateAuthorizationUrl(value, BASE), AccountLoginError)
  })
}

test('session requires the agreed UUID and UTC expiration', () => {
  assert.deepEqual(validateSession(SESSION), SESSION)
  assert.deepEqual(validateSession({ authenticated: false }), { authenticated: false })
  assert.deepEqual(validateSession({ ...SESSION, expires_at: '2000-10-04T12:00:00Z' }), { authenticated: false })
})

for (const value of [null, { authenticated: true }, { ...SESSION, account_id: '42' }, { ...SESSION, password: 'do-not-echo' },
  { ...SESSION, expires_at: '2099-10-04T12:00:00+00:00' }, { ...SESSION, expires_at: '2099-99-99T12:00:00Z' }]) {
  test('malformed session is not treated as authenticated', () => assert.throws(() => validateSession(value), AccountLoginError))
}

test('start/session/logout send cookies and fixed JSON without persistence', async () => {
  const { client, calls } = mockClient([{ body: { authorization_url: VALID_URL } }, { body: SESSION },
    { body: { status: 'success', authenticated: false } }])
  assert.equal(await client.start(), VALID_URL)
  assert.deepEqual(await client.session(), SESSION)
  await client.logout()
  assert.deepEqual(calls.map(([url]) => url), ['http://localhost:8000/api/auth/nagecen/start',
    'http://localhost:8000/api/auth/session', 'http://localhost:8000/api/auth/logout'])
  for (const [, options] of calls) {
    assert.equal(options.credentials, 'include')
    assert.equal(options.redirect, 'error')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.referrerPolicy, 'no-referrer')
  }
  assert.equal(calls[0][1].body, '{}')
  assert.equal(calls[1][1].body, undefined)
  assert.equal(calls[2][1].body, '{}')
})

test('one callback task shares one POST under repeated StrictMode effects', async () => {
  const { client, calls } = mockClient([{ body: { status: 'success', redirect_path: '/check' } }, { body: SESSION }])
  const task = createCallbackTask(PAYLOAD, client)
  const first = task()
  assert.equal(task(), first)
  assert.deepEqual(await first, { status: 'success', redirect_path: '/check' })
  assert.equal(task(), first)
  assert.equal(calls.length, 2)
  assert.equal(calls[0][1].body, JSON.stringify(PAYLOAD))
})

test('cancelled callback never checks or creates a new account session', async () => {
  const { client, calls } = mockClient([{ body: { status: 'cancelled', redirect_path: '/' } }])
  const task = createCallbackTask({ state: PAYLOAD.state, error: 'access_denied' }, client)
  assert.deepEqual(await task(), { status: 'cancelled', redirect_path: '/' })
  assert.equal(calls.length, 1)
})

test('failed callback is never automatically retried and does not echo server secrets', async () => {
  const { client, calls } = mockClient([{ status: 410, body: { code: 'login_expired', message: 'private-secret-not-to-echo' } }])
  const task = createCallbackTask(PAYLOAD, client)
  await assert.rejects(task(), (error) => error.code === 'login_expired' && !error.message.includes('private-secret'))
  await assert.rejects(task(), AccountLoginError)
  assert.equal(calls.length, 1)
})

test('invalid callback never contacts the API', async () => {
  const { client, calls } = mockClient([])
  await assert.rejects(createCallbackTask({ invalid: true }, client)(), (error) => error.code === 'invalid_callback')
  assert.equal(calls.length, 0)
})

test('success cannot redirect without a server-verified account session', async () => {
  const { client } = mockClient([{ body: { status: 'success', redirect_path: '/check' } }, { body: { authenticated: false } }])
  await assert.rejects(createCallbackTask(PAYLOAD, client)(), (error) => error.code === 'login_required')
})

test('arbitrary callback redirect is rejected', async () => {
  const { client, calls } = mockClient([{ body: { status: 'success', redirect_path: 'https://evil.example/' } }])
  await assert.rejects(createCallbackTask(PAYLOAD, client)(), (error) => error.code === 'invalid_response')
  assert.equal(calls.length, 1)
})

test('non-JSON/oversized/unknown-error responses are sanitized', async () => {
  for (const next of [{ body: {}, type: 'text/plain' }, { body: 'secret'.repeat(2000) },
    { status: 500, body: { code: 'secret-code', message: 'secret-message' } }]) {
    const { client } = mockClient([next])
    await assert.rejects(client.start(), (error) => error instanceof AccountLoginError && !error.message.includes('secret'))
  }
})

test('network error is not retried or shown verbatim', async () => {
  let calls = 0
  const client = createAccountClient({ fetcher: async () => { calls += 1; throw new Error('private-network-details') } })
  await assert.rejects(client.start(), (error) => error.code === 'network_error' && !error.message.includes('private-network'))
  assert.equal(calls, 1)
})

test('diagnostic API includes account cookies and signals expiration on 401 only', async () => {
  for (const status of [200, 401, 403, 404, 503]) {
    let expired = 0
    const fetcher = async (url, options) => {
      assert.equal(options.credentials, 'include')
      assert.equal(options.cache, 'no-store')
      assert.equal(options.referrerPolicy, 'no-referrer')
      assert.equal(options.body, '{}')
      return { status }
    }
    await diagnosticRequest(fetcher, true, () => { expired += 1 }, '/api/scan-jobs/id/cancel', { method: 'POST', body: '{}' })
    assert.equal(expired, status === 401 ? 1 : 0)
  }
})

test('legacy diagnostic requests keep their exact previous options', async () => {
  const options = { method: 'POST', body: '{}' }
  const fetcher = async (url, actual) => { assert.equal(actual, options); return { status: 401 } }
  await diagnosticRequest(fetcher, false, () => assert.fail(), '/api/scan-jobs', options)
})
