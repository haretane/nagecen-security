import test from 'node:test'
import assert from 'node:assert/strict'
import { createDemoClient } from '../src/diagnostic-demo-client.mjs'

test('demo completes with fictional findings without HTTP, storage or credentials retention', async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = () => { throw new Error('Demo must not access the network') }
  try {
    const client = createDemoClient()
    const validated = await client.validate('https://test.example.com/#test')
    const tag = await client.issue(validated.normalized_url)
    assert.match(tag.meta_tag, /nagecen-site-verification/)
    assert.match(tag.token, /^PREVIEW-NOT-VALID-/)
    assert.equal(Date.parse(tag.expires_at) - Date.parse(tag.created_at), 30 * 60_000)
    const verified = await client.confirm(tag)
    assert.equal(verified.verified, true)
    const job = await client.start({ level_id: 'xss', authentication_type: 'form',
      form_authentication: { identifier: 'fake-user', password: 'fake-secret' } })
    assert.equal(job.status, 'queued')
    assert.equal(JSON.stringify(job).includes('fake-secret'), false)
    await new Promise(resolve => setTimeout(resolve, 9000))
    const completed = await client.job(job.id)
    assert.equal(completed.status, 'completed')
    assert.equal(completed.findings.length, 3)
    assert.ok(completed.findings.every(item => item.description.includes('架空')))
    assert.equal(JSON.stringify(completed).includes('fake-secret'), false)
  } finally { globalThis.fetch = originalFetch }
})

test('cancelled demo never proceeds to running or results', async () => {
  const client = createDemoClient()
  await client.issue('https://test.example.com/')
  const job = await client.start({ level_id: 'basic', authentication_type: 'none' })
  assert.equal((await client.cancel(job.id)).status, 'cancelled')
  assert.equal((await client.job(job.id)).status, 'cancelled')
})
