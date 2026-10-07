import test from 'node:test'
import assert from 'node:assert/strict'
import { createPreparationClient } from '../src/account-login/preparation-client.mjs'

const id = 'e527baf7-1a41-4095-88c1-5e7838462255'
const url = 'https://test.example.com/'
const tag = { verification_id: id, target_url: url, token: 'TEST-ONLY-TOKEN', meta_tag: '<meta name="test" content="TEST-ONLY-TOKEN">', expires_at: new Date(Date.now() + 1800000).toISOString() }
test('preparation uses only the three existing APIs with account credentials', async () => {
  const calls = []
  const client = createPreparationClient({ apiBase: 'http://localhost:8000/', fetchImpl: async (url, options) => {
    calls.push({ url, options })
    return Response.json(calls.length === 1 ? { valid: true, normalized_url: 'https://test.example.com/' } : calls.length === 2 ? tag : { verified: true, verified_target_id: id })
  } })
  await client.validate(url)
  await client.issue(url)
  await client.confirm(tag)
  assert.deepEqual(calls.map(call => new URL(call.url).pathname), ['/api/url-validation', '/api/site-verifications', `/api/site-verifications/${id}/confirm`])
  for (const { options } of calls) {
    assert.equal(options.credentials, 'include')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.referrerPolicy, 'no-referrer')
    assert.equal(options.redirect, 'error')
    assert.ok(options.signal instanceof AbortSignal)
  }
  assert.deepEqual(JSON.parse(calls[2].options.body), { token: tag.token })
})
test('401 expires the account without surfacing raw API contents', async () => {
  let expired = 0
  const client = createPreparationClient({ apiBase: '', onSessionExpired: () => expired++, fetchImpl: async () => Response.json({ detail: { code: 'login_required', message: 'RAW-SENSITIVE-CONTENT' } }, { status: 401 }) })
  await assert.rejects(client.validate(url), error => error.status === 401 && !error.message.includes('RAW-SENSITIVE'))
  assert.equal(expired, 1)
})
test('meta-not-found is available for bounded automatic retry', async () => {
  const client = createPreparationClient({ apiBase: '', fetchImpl: async () => Response.json({ detail: { code: 'meta_not_found' } }, { status: 422 }) })
  await assert.rejects(client.confirm(tag), error => error.code === 'meta_not_found')
})
for (const payload of [{}, { verification_id: id, expires_at: 'bad' }]) {
  test('malformed issue response is rejected', async () => {
    const client = createPreparationClient({ apiBase: '', fetchImpl: async () => Response.json(payload) })
    await assert.rejects(client.issue(url))
  })
}
test('HTML API responses are rejected', async () => {
  const client = createPreparationClient({ apiBase: '', fetchImpl: async () => new Response('<html>error</html>', { headers: { 'Content-Type': 'text/html' } }) })
  await assert.rejects(client.validate(url))
})

test('jobs use authenticated POST, GET and cancel without any automatic submission', async () => {
  const calls = []
  const client = createPreparationClient({ apiBase: '', fetchImpl: async (url, options) => {
    calls.push({ url, options })
    return Response.json({ id, status: 'queued', target_url: 'https://test.example.com/', findings: [] })
  } })
  assert.equal(calls.length, 0)
  await client.start({ verified_target_id: id, level_id: 'basic' })
  await client.job(id)
  await client.cancel(id)
  assert.deepEqual(calls.map(call => call.options.method), ['POST', 'GET', 'POST'])
  assert.equal(calls[1].options.body, undefined)
  assert.equal(calls[2].url, `/api/scan-jobs/${id}/cancel`)
  assert.ok(calls.every(call => call.options.credentials === 'include'))
})

test('malformed job response does not become a result', async () => {
  const client = createPreparationClient({ apiBase: '', fetchImpl: async () => Response.json({ id, status: 'completed' }) })
  await assert.rejects(client.job(id), /invalid_response/)
})
