import assert from 'node:assert/strict'
// Optional runner: install Playwright outside the project, then point to its module.
const { chromium } = await import(process.env.ACCOUNT_LOGIN_PLAYWRIGHT_MODULE ?? 'playwright')
const artifactDir = process.env.ACCOUNT_LOGIN_BROWSER_ARTIFACT_DIR
if (!artifactDir) throw new Error('Specify a temporary ACCOUNT_LOGIN_BROWSER_ARTIFACT_DIR')
const { mkdir } = await import('node:fs/promises')
await mkdir(artifactDir, { recursive: true })

const browser = await chromium.launch({ executablePath: process.env.ACCOUNT_LOGIN_BROWSER_EXECUTABLE ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true })
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } })
const errors = []
let previews = 0
context.on('page', page => page.on('pageerror', error => errors.push(error.message)))
const page = await context.newPage()
try {
  let previewApiCalls = 0
  await page.route('**/api/**', async route => { previewApiCalls += 1; await route.abort() })
  await page.goto('http://localhost:5174/preview/account-login')
  await page.getByRole('button', { name: 'ログインして始める', exact: true }).click()
  await page.getByRole('heading', { name: 'NAGeCenアカウントで始める', exact: true }).waitFor()
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 1000 })
    for (const view of ['top', 'login', 'loggedIn', 'expired', 'callback', 'cancelled', 'loggedOut', 'error']) {
      await page.locator('#account-preview-view').selectOption(view)
      await page.locator(view === 'top' || view === 'loggedIn' ? '.landing-hero' : '.account-card').waitFor()
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth), false, `overflow: ${width}/${view}`)
      await page.screenshot({ path: `${artifactDir}/${width}-${view}.png`, fullPage: true })
      previews += 1
    }
  }
  assert.equal(previewApiCalls, 0)
  await page.unroute('**/api/**')

  let authenticated = false
  let accountId = 'e527baf7-1a41-4095-88c1-5e7838462255'
  let validationExpired = false
  let sessionUnavailable = false
  const counts = { start: 0, complete: 0, logout: 0, diagnostics: 0 }
  await context.route('**/api/**', async route => {
    console.log(JSON.stringify({ unexpectedApiHost: new URL(route.request().url()).host, path: new URL(route.request().url()).pathname }))
    await route.abort()
  })
  const session = () => authenticated ? { authenticated: true, account_id: accountId,
    expires_at: new Date(Date.now() + 3600000).toISOString() } : { authenticated: false }
  await context.route('http://localhost:8000/**', async route => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const headers = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'http://localhost:5175',
      'Access-Control-Allow-Credentials': 'true', 'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'GET, POST', 'Cache-Control': 'no-store' }
    if (request.method() === 'OPTIONS') return route.fulfill({ status: 204, headers })
    let status = 200
    let body
    if (path === '/api/auth/session') {
      status = sessionUnavailable ? 503 : 200
      body = sessionUnavailable ? { code: 'login_unavailable' } : session()
    } else if (path === '/api/auth/nagecen/start') {
      counts.start += 1
      assert.equal(request.postData(), '{}')
      body = { authorization_url: `http://localhost:5173/nagecen/security-login?client_id=nagecen-security&state=${'A'.repeat(43)}&code_challenge=${'B'.repeat(43)}&code_challenge_method=S256` }
    } else if (path === '/api/auth/nagecen/complete') {
      counts.complete += 1
      const input = request.postDataJSON()
      if (input.error === 'access_denied') body = { status: 'cancelled', redirect_path: '/' }
      else {
        authenticated = true
        headers['Set-Cookie'] = `nagecen_security_account_session_dev=${'T'.repeat(43)}; Path=/; HttpOnly; SameSite=Lax`
        body = { status: 'success', redirect_path: '/check' }
      }
    } else if (path === '/api/auth/logout') {
      counts.logout += 1
      assert.equal(request.postData(), '{}')
      authenticated = false
      headers['Set-Cookie'] = 'nagecen_security_account_session_dev=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax'
      body = { status: 'success', authenticated: false }
    } else if (path === '/health') body = { status: 'ok', database: 'connected' }
    else if (path === '/api/scan-jobs/levels') {
      counts.diagnostics += 1
      assert.ok(request.headers().cookie?.includes('nagecen_security_account_session_dev='))
      body = [{ id: 'basic', display_name: 'Lv.1', description: '基本セーフティチェック', available: true,
        check_ids: [], active_rule_ids: [], scan_mode: 'baseline', price_label: '無料' }]
    } else if (path === '/api/url-validation') {
      counts.diagnostics += 1
      if (validationExpired) { status = 401; body = { code: 'login_required' }; authenticated = false }
      else body = { valid: true, normalized_url: request.postDataJSON().url, hostname: 'test.example' }
    } else {
      throw new Error(`Unmocked API path: ${path}`)
    }
    return route.fulfill({ status, headers, body: JSON.stringify(body) })
  })
  await context.route('http://localhost:5173/**', route => route.fulfill({ contentType: 'text/html; charset=utf-8', body: '<meta charset="UTF-8"><h1>模擬NAGeCenログイン</h1>' }))
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto('http://localhost:5175/check')
  await page.getByRole('heading', { name: 'NAGeCenアカウントで始める', exact: true }).waitFor()
  assert.equal(await page.locator('#preparation-url').count(), 0)
  assert.equal(counts.diagnostics, 0)
  await page.getByRole('button', { name: 'NAGeCenでログイン・新規登録', exact: true }).click()
  try { await page.getByRole('heading', { name: '模擬NAGeCenログイン' }).waitFor({ timeout: 10000 }) }
  catch (error) {
    console.log(JSON.stringify({ counts, feedback: await page.locator('.account-feedback').allTextContents(), path: new URL(page.url()).pathname }))
    await page.screenshot({ path: `${artifactDir}/failure.png`, fullPage: true })
    throw error
  }
  assert.equal(counts.start, 1)
  await page.goto(`http://localhost:5175/auth/nagecen/callback?state=${'A'.repeat(43)}&code=${'C'.repeat(43)}`)
  await page.getByRole('checkbox').check()
  await page.getByRole('button', { name: 'URL入力へ', exact: true }).click()
  await page.locator('#preparation-url').waitFor()
  assert.equal(new URL(page.url()).pathname, '/check')
  assert.equal(counts.complete, 1)
  assert.equal(await page.evaluate(() => localStorage.getItem('nagecen_security_last_scan_job_id')), null)
  await page.locator('#preparation-url').fill('https://private-test.example/')
  await page.screenshot({ path: `${artifactDir}/authenticated-check.png`, fullPage: true })

  // Server rejects the next operation after expiration: discard the form.
  validationExpired = true
  await page.getByRole('button', { name: 'タグ設置へ', exact: true }).click()
  await page.getByRole('heading', { name: 'もう一度ログインしてください', exact: true }).waitFor()
  assert.equal(await page.locator('#preparation-url').count(), 0)
  assert.equal((await page.locator('body').innerText()).includes('https://private-test.example/'), false)
  validationExpired = false

  // Cancellation cleans the browser URL, and repeated effects send one POST.
  await page.goto(`http://localhost:5175/auth/nagecen/callback?state=${'A'.repeat(43)}&error=access_denied`)
  await page.getByRole('heading', { name: 'ログインを中止しました', exact: true }).waitFor()
  assert.equal(new URL(page.url()).search, '')
  assert.equal(counts.complete, 2)
  await page.goto(`http://localhost:5175/auth/nagecen/callback?state=wrong&code=wrong`)
  await page.getByRole('heading', { name: 'ログインを確認できませんでした', exact: true }).waitFor()
  assert.equal(new URL(page.url()).search, '')
  assert.equal(counts.complete, 2)

  // A login in another tab must discard the previous user's form/results.
  await page.goto(`http://localhost:5175/auth/nagecen/callback?state=${'A'.repeat(43)}&code=${'C'.repeat(43)}`)
  await page.getByRole('checkbox').check()
  await page.getByRole('button', { name: 'URL入力へ', exact: true }).click()
  await page.locator('#preparation-url').fill('https://old-account.example/')
  const other = await context.newPage()
  accountId = '295fe1dc-a007-4f94-95a8-a6b749e6e9b0'
  await other.goto(`http://localhost:5175/auth/nagecen/callback?state=${'D'.repeat(43)}&code=${'E'.repeat(43)}`)
  await other.getByRole('heading', { name: '診断の準備', exact: true }).waitFor()
  await page.getByRole('checkbox').waitFor()
  await page.waitForFunction(() => document.querySelector('#preparation-url') === null)
  await other.getByRole('button', { name: 'ログアウト', exact: true }).click()
  await other.getByRole('heading', { name: 'ログアウトしました', exact: true }).waitFor()
  await page.getByRole('heading', { name: 'もう一度ログインしてください', exact: true }).waitFor()
  assert.equal(counts.logout, 1)
  assert.equal(await page.locator('#preparation-url').count(), 0)

  sessionUnavailable = true
  await page.goto('http://localhost:5175/check')
  await page.getByRole('heading', { name: 'ログインを確認できませんでした', exact: true }).waitFor()
  assert.equal(await page.locator('#preparation-url').count(), 0)
  sessionUnavailable = false
  await page.getByRole('button', { name: '接続を再確認する', exact: true }).click()
  await page.getByRole('heading', { name: 'NAGeCenアカウントで始める', exact: true }).waitFor()
  await page.goto('http://localhost:5175/integrations/nagecen?token=legacy-placeholder')
  await page.getByRole('heading', { name: '従来の連携は切り替え準備中です', exact: true }).waitFor()

  // Disabled-mode callback still scrubs credentials without an API exchange.
  const disabledBase = process.env.ACCOUNT_LOGIN_DISABLED_BASE ?? 'http://localhost:5177'
  await page.goto(`${disabledBase}/auth/nagecen/callback?state=${'A'.repeat(43)}&code=${'C'.repeat(43)}`)
  await page.getByRole('heading', { name: 'ログイン連携は準備中です', exact: true }).waitFor()
  assert.equal(new URL(page.url()).search, '')
  assert.equal(counts.complete, 4)
  assert.deepEqual(errors, [])
  console.log(JSON.stringify({ previewScreens: previews, previewApiCalls, mockedAuthChecks: 'passed', callbackPosts: counts.complete, browserErrors: errors.length }))
} finally {
  await context.close()
  await browser.close()
}
