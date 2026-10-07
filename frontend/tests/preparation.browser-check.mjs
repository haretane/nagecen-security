import assert from 'node:assert/strict'
const { chromium } = await import(process.env.ACCOUNT_LOGIN_PLAYWRIGHT_MODULE ?? 'playwright')
const browser = await chromium.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true })
const base = 'http://127.0.0.1:5176'
const id = 'e527baf7-1a41-4095-88c1-5e7838462255'
let authenticated = true
let scenario = 'success'
let confirmCount = 0
let issueCount = 0
let scanCalls = 0
const errors = []
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } })
page.on('pageerror', error => errors.push(error.message))
await page.clock.install()
await page.addInitScript(() => {
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
    writeText: async value => {
      if (window.__copyFailure) throw new Error('mock-denied')
      window.__copiedTag = value
    },
  } })
})
await page.route('**/api/**', async route => {
  const request = route.request()
  const path = new URL(request.url()).pathname
  const headers = { 'Access-Control-Allow-Origin': base, 'Access-Control-Allow-Credentials': 'true', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'GET, POST', 'Content-Type': 'application/json' }
  if (request.method() === 'OPTIONS') return route.fulfill({ status: 204, headers })
  let status = 200
  let body
  if (path === '/api/auth/session') body = authenticated ? { authenticated: true, account_id: id, expires_at: new Date(Date.now() + 3600000).toISOString() } : { authenticated: false }
  else if (path === '/api/auth/logout') { authenticated = false; body = { authenticated: false, status: 'success' } }
  else if (path === '/api/url-validation') {
    if (scenario === '401') { authenticated = false; status = 401; body = { code: 'login_required' } }
    else if (scenario === 'invalid-url') { status = 422; body = { detail: { code: 'private_ip' } } }
    else body = { valid: true, normalized_url: request.postDataJSON().url, hostname: 'test.example.com' }
  } else if (path === '/api/site-verifications') {
    issueCount++
    body = { verification_id: id, target_url: request.postDataJSON().url, token: 'MOCK-TOKEN-NOT-FOR-REAL-SITE', meta_tag: '<meta name="nagecen-security-verification" content="MOCK-TOKEN-NOT-FOR-REAL-SITE">', expires_at: new Date(Date.now() + 1800000).toISOString() }
  } else if (path.endsWith('/confirm')) {
    confirmCount++
    if (scenario === 'missing' || (scenario === 'retry-success' && confirmCount === 1)) { status = 422; body = { detail: { code: 'meta_not_found' } } }
    else if (scenario === 'expired') { status = 410; body = { detail: { code: 'expired' } } }
    else if (scenario === '429') { status = 429; body = { detail: { code: 'confirmation_limit_reached' } } }
    else body = { verified: true, verified_target_id: id }
  } else { scanCalls++; throw new Error(`Unexpected API: ${path}`) }
  return route.fulfill({ status, headers, body: JSON.stringify(body) })
})
async function enterUrl(width = 1440) {
  authenticated = true
  confirmCount = 0
  await page.setViewportSize({ width, height: 1000 })
  await page.goto(`${base}/check`)
  await page.locator('.wizard-card h2').waitFor()
  assert.equal(await page.locator('.wizard-card h2').evaluate(node => getComputedStyle(node).outlineStyle), 'none')
  await page.getByRole('checkbox').check()
  await page.getByRole('button', { name: 'URL入力へ', exact: true }).click()
  await page.locator('#preparation-url').fill('https://test.example.com/')
}
async function issueTag() {
  await enterUrl()
  await page.getByRole('button', { name: 'タグ設置へ', exact: true }).click()
  await page.getByRole('button', { name: 'タグをコピー', exact: true }).waitFor()
}
try {
  for (const width of [1440, 390]) {
    scenario = 'success'
    await enterUrl(width)
    await page.getByRole('button', { name: 'タグ設置へ', exact: true }).click()
    await page.getByRole('heading', { name: '編集・管理権限の確認用タグ', exact: true }).waitFor()
    assert.equal(await page.locator('.wizard-tag-section').evaluate(node => parseFloat(getComputedStyle(node).marginTop)), 32)
    await page.getByRole('heading', { name: 'なぜタグを埋め込むの？', exact: true }).waitFor()
    await page.getByRole('button', { name: 'タグをコピー', exact: true }).click()
    await page.getByRole('button', { name: 'コピーしました', exact: true }).waitFor()
    assert.equal(await page.evaluate(() => window.__copiedTag), await page.locator('.wizard-code code').innerText())
    assert.equal(await page.locator('.wizard-tag-copy-button').evaluate(node => getComputedStyle(node).color), 'rgb(0, 108, 68)')
    await page.clock.runFor(2600)
    await page.getByRole('button', { name: 'タグをコピー', exact: true }).waitFor()
    await page.evaluate(() => { window.__copyFailure = true })
    await page.getByRole('button', { name: 'タグをコピー', exact: true }).click()
    await page.getByText('コピーできませんでした。タグを選択してコピーしてください。', { exact: true }).waitFor()
    assert.equal(await page.getByRole('button', { name: 'コピーしました', exact: true }).count(), 0)
    await page.getByRole('button', { name: 'タグの設置を確認する', exact: true }).click()
    await page.getByText('テストサイトの管理権限を確認できました。', { exact: true }).waitFor()
    assert.equal(confirmCount, 1)
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false)
    assert.equal(await page.getByRole('button', { name: '診断内容の選択へ' }).count(), 1)
    await page.screenshot({ path: `/private/tmp/security-preparation-${width}.png`, fullPage: true })
    await page.reload()
    await page.getByRole('heading', { name: '診断の準備', exact: true }).waitFor()
    assert.equal(await page.getByText('テストサイトの管理権限を確認できました。', { exact: true }).count(), 0)
  }
  scenario = 'retry-success'
  await issueTag()
  await page.getByRole('button', { name: 'タグの設置を確認する', exact: true }).click()
  await page.getByText('タグの反映待ちの可能性があるため、少し時間をおいて、タグの設置をもう一度だけ自動で確認します。', { exact: true }).waitFor()
  const dot = page.locator('.wizard-loading-dots span').first()
  assert.equal(await dot.evaluate(node => getComputedStyle(node).width), '7px')
  assert.equal(await dot.evaluate(node => getComputedStyle(node).animationName), 'wizard-dot-pulse')
  await page.emulateMedia({ reducedMotion: 'reduce' })
  assert.equal(await dot.evaluate(node => getComputedStyle(node).animationName), 'none')
  await page.emulateMedia({ reducedMotion: 'no-preference' })
  await page.clock.runFor(21000)
  await page.getByText('テストサイトの管理権限を確認できました。', { exact: true }).waitFor()
  assert.equal(confirmCount, 2)
  scenario = 'missing'
  await issueTag()
  await page.getByRole('button', { name: 'タグの設置を確認する', exact: true }).click()
  await page.getByText('タグの反映待ちの可能性があるため、少し時間をおいて、タグの設置をもう一度だけ自動で確認します。', { exact: true }).waitFor()
  await page.clock.runFor(21000)
  await page.getByText('確認タグが見つかりませんでした。', { exact: true }).waitFor()
  assert.equal(confirmCount, 2)
  await page.clock.runFor(21000)
  assert.equal(confirmCount, 2)
  await page.getByRole('button', { name: 'タグの設置を確認する', exact: true }).click()
  await page.getByText('タグの反映待ちの可能性があるため、少し時間をおいて、タグの設置をもう一度だけ自動で確認します。', { exact: true }).waitFor()
  await page.getByRole('button', { name: '戻る', exact: true }).click()
  const stopped = confirmCount
  await page.clock.runFor(21000)
  assert.equal(confirmCount, stopped)
  for (const failure of ['expired', '429']) {
    scenario = failure
    await issueTag()
    await page.getByRole('button', { name: 'タグの設置を確認する', exact: true }).click()
    await (failure === 'expired' ? page.getByText('確認タグの有効期限が切れました。', { exact: true }) : page.getByRole('alert')).waitFor()
    assert.equal(confirmCount, 1)
  }
  scenario = 'invalid-url'
  await enterUrl()
  const before = issueCount
  await page.getByRole('button', { name: 'タグ設置へ', exact: true }).click()
  await page.getByRole('alert').waitFor()
  assert.equal(issueCount, before)
  scenario = '401'
  await enterUrl()
  await page.getByRole('button', { name: 'タグ設置へ', exact: true }).click()
  await page.getByRole('heading', { name: 'もう一度ログインしてください', exact: true }).waitFor()
  assert.equal(await page.locator('#preparation-url').count(), 0)
  assert.equal(scanCalls, 0)
  assert.deepEqual(errors, [])
  console.log('Preparation browser checks passed: PC/mobile, bounded retry, cancellation, expiry, rate limit, rejected URL, session expiry; no scan API called.')
} finally { await browser.close() }
