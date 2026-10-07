import assert from 'node:assert/strict'
const { chromium } = await import(process.env.ACCOUNT_LOGIN_PLAYWRIGHT_MODULE ?? 'playwright')
const browser = await chromium.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true })
const base = 'http://localhost:5174'
const id = 'e527baf7-1a41-4095-88c1-5e7838462255'
const url = 'https://test.example.com/'
let status = 'queued', starts = [], polls = 0, errors = [], unexpected = 0
const job = () => ({ id, status, level_id: 'xss', target_url: url, crawled_url_count: 3,
  finished_at: '2026-10-06T04:00:00Z', checked_items: [{ id: 'security_headers', label: 'セキュリティヘッダー' }],
  incomplete_items: [], unchecked_items: [{ id: 'sql', label: 'SQLインジェクション' }],
  authentication_message: 'ログインなしで見られる範囲を診断しました。',
  findings: status === 'completed' ? [{ rule_id: '10038', risk: 'medium', title: 'CSPヘッダー未設定', technical_title: 'CSP Header Not Set',
    description: '設定を確認してください。', solution: 'テスト環境で設定を確認してください。', confidence_label: '高',
    locations: [{ url, method: 'GET', parameter: '' }], ai_prompt: 'Mock finding: inspect CSP configuration.' }] : [],
})
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } })
page.on('pageerror', error => errors.push(error.message))
await page.route('**/api/**', async route => {
  const request = route.request(), path = new URL(request.url()).pathname
  const headers = { 'Access-Control-Allow-Origin': base, 'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'GET, POST', 'Content-Type': 'application/json' }
  if (request.method() === 'OPTIONS') return route.fulfill({ status: 204, headers })
  let data
  if (path === '/api/auth/session') data = { authenticated: true, account_id: id, expires_at: new Date(Date.now() + 3600000).toISOString() }
  else if (path === '/api/url-validation') data = { valid: true, normalized_url: url }
  else if (path === '/api/site-verifications') data = { verification_id: id, target_url: url, token: 'MOCK-ONLY-NOT-A-REAL-TOKEN', meta_tag: '<meta name="mock" content="mock">', expires_at: new Date(Date.now() + 1800000).toISOString() }
  else if (path.endsWith('/confirm')) data = { verified: true, verified_target_id: id }
  else if (path === '/api/scan-jobs') { starts.push(request.postDataJSON()); data = job() }
  else if (path === `/api/scan-jobs/${id}/cancel`) { status = 'cancelled'; data = job() }
  else if (path === `/api/scan-jobs/${id}`) { polls++; data = job() }
  else { unexpected++; return route.abort() }
  await route.fulfill({ status: 200, headers, body: JSON.stringify(data) })
})
async function prepare() {
  await page.goto(base + '/check')
  await page.getByRole('checkbox').check()
  await page.getByRole('button', { name: 'URL入力へ', exact: true }).click()
  await page.locator('#preparation-url').fill(url)
  await page.getByRole('button', { name: 'タグ設置へ', exact: true }).click()
  await page.getByRole('button', { name: 'タグの設置を確認する', exact: true }).click()
  await page.getByRole('button', { name: '診断内容の選択へ', exact: true }).click()
  await page.getByRole('heading', { name: '診断内容を選択', exact: true }).waitFor()
}
try {
  await prepare()
  await page.screenshot({ path: '/private/tmp/security-execution-options.png', fullPage: true })
  assert.equal(starts.length, 0)
  await page.getByRole('button', { name: 'URLを変更する', exact: true }).click()
  await page.getByRole('button', { name: '変更せず戻る', exact: true }).click()
  await page.getByLabel('XSS確認を追加する（反射型）', { exact: true }).check()
  await page.getByRole('button', { name: '実行前の確認へ', exact: true }).click()
  assert.equal(await page.getByRole('button', { name: '診断を開始する', exact: true }).isDisabled(), true)
  await page.getByRole('checkbox').check()
  await page.getByRole('button', { name: '診断を開始する', exact: true }).dblclick()
  await page.getByRole('heading', { name: '診断の順番待ちです', exact: true }).waitFor()
  assert.equal(starts.length, 1)
  assert.equal(starts[0].verified_target_id, id)
  assert.equal(starts[0].level_id, 'xss')
  assert.equal(starts[0].active_scan_confirmed, true)
  assert.equal(starts[0].authentication_type, 'none')
  assert.equal(starts[0].form_authentication, undefined)
  await page.reload()
  await page.getByRole('heading', { name: '診断の順番待ちです', exact: true }).waitFor()
  assert.equal(starts.length, 1)
  await page.getByRole('button', { name: '順番待ちを中止する', exact: true }).click()
  await page.getByRole('heading', { name: '順番待ちを中止しました', exact: true }).waitFor()
  status = 'running'
  await page.reload()
  await page.getByRole('heading', { name: 'テストサイトを診断しています', exact: true }).waitFor()
  assert.equal(await page.getByRole('button', { name: '順番待ちを中止する', exact: true }).count(), 0)
  status = 'completed'
  await page.getByRole('button', { name: '状況を再確認する', exact: true }).click()
  await page.getByRole('heading', { name: '確認した内容・改善の候補', exact: true }).waitFor()
  await page.getByRole('heading', { name: 'CSPヘッダー未設定', exact: true }).waitFor()
  assert.equal(await page.getByText('検出の確信度：高', { exact: false }).count(), 1)
  assert.equal(await page.getByRole('button', { name: 'この区分をまとめてコピー', exact: true }).count(), 0)
  await page.getByRole('button', { name: '内容を見る', exact: true }).first().click()
  assert.match(await page.locator('dialog[open] textarea').inputValue(), /Mock finding/)
  await page.getByRole('button', { name: '閉じる', exact: true }).click()
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 1000 })
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false)
    await page.screenshot({ path: `/private/tmp/security-live-result-${width}.png`, fullPage: true })
  }
  status = 'failed'; await page.reload()
  await page.getByRole('heading', { name: '診断を完了できませんでした', exact: true }).waitFor()
  assert.equal(await page.getByRole('heading', { name: '確認した内容・改善の候補', exact: true }).count(), 0)
  status = 'queued'; await prepare()
  await page.getByLabel('ログイン後のページも含める', { exact: true }).check()
  await page.locator('#diagnostic-login-url').fill(url + 'login')
  await page.locator('#diagnostic-login-id').fill('mock-test-user')
  await page.locator('#diagnostic-login-password').fill('MOCK-NOT-REAL')
  await page.getByRole('button', { name: '実行前の確認へ', exact: true }).click()
  await page.getByRole('checkbox').check()
  await page.getByRole('button', { name: '診断を開始する', exact: true }).click()
  await page.getByRole('heading', { name: '診断の順番待ちです', exact: true }).waitFor()
  assert.equal(starts[1].authentication_type, 'form')
  assert.equal(starts[1].form_authentication.password, 'MOCK-NOT-REAL')
  assert.deepEqual(errors, []); assert.equal(unexpected, 0)
  console.log(JSON.stringify({ mockedStarts: starts.length, polls, unexpectedAPIs: unexpected, browserErrors: errors.length }))
} finally { await browser.close() }
