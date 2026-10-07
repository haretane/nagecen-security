// Deliberately has no fetch, storage, cookies or backend dependencies.
// IDs and tokens exist only in memory and never authorize a real scan.
export function createDemoClient() {
  let targetUrl, currentJob, startedAt
  async function pause(signal) {
    await new Promise((resolve, reject) => {
      if (signal?.aborted) return reject(new Error('aborted'))
      const abort = () => { clearTimeout(timer); reject(new Error('aborted')) }
      const timer = setTimeout(() => { signal?.removeEventListener('abort', abort); resolve() }, 800)
      signal?.addEventListener('abort', abort, { once: true })
    })
  }
  const finding = (rule, risk, title, description, solution) => ({
    rule_id: rule, risk, title, technical_title: ({ '40012': 'Cross Site Scripting (Reflected)', '10038': 'Content Security Policy (CSP) Header Not Set', '10035': 'Strict-Transport-Security Header Not Set' }[rule] || title), confidence_label: '高',
    description: '【架空の表示例】' + description, solution,
    locations: [{ url: targetUrl, method: 'GET' }],
  })
  return {
    async validate(input, signal) {
      await pause(signal)
      const url = new URL(input)
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('invalid_url')
      url.hash = ''
      return { normalized_url: url.href }
    },
    async issue(url, signal) {
      await pause(signal)
      targetUrl = url
      const token = 'PREVIEW-NOT-VALID-' + crypto.randomUUID()
      const created = new Date()
      return { verification_id: crypto.randomUUID(), token, target_url: url,
        target_host: new URL(url).hostname,
        meta_tag: `<meta name="nagecen-site-verification" content="${token}">`,
        created_at: created.toISOString(), expires_at: new Date(+created + 30 * 60_000).toISOString() }
    },
    async confirm(tag, signal) {
      await pause(signal)
      if (Date.now() >= Date.parse(tag.expires_at)) throw Object.assign(new Error('expired'), { code: 'expired' })
      return { verified: true, verified_target_id: crypto.randomUUID() }
    },
    async start(request, signal) {
      await pause(signal)
      // Never retain the form_authentication object or its credentials.
      startedAt = Date.now()
      currentJob = { id: crypto.randomUUID(), status: 'queued', target_url: targetUrl,
        level_id: request.level_id, crawled_url_count: 0, findings: [],
        authentication_message: request.authentication_type === 'form' ? 'ログイン設定あり（模擬・未実行）' : 'ログインなし（表示例）',
        checked_items: [{ id: 'headers', label: '応答ヘッダーの確認（表示例）' }],
        unchecked_items: [{ id: 'stored', label: '保存型XSS・DOM型XSS・SQLインジェクション' }], incomplete_items: [] }
      return { ...currentJob }
    },
    async job(id, signal) {
      await pause(signal)
      if (!currentJob || currentJob.id !== id) throw new Error('not_found')
      if (currentJob.status === 'cancelled') return { ...currentJob }
      const elapsed = Date.now() - startedAt
      const status = elapsed < 3500 ? 'queued' : elapsed < 9000 ? 'running' : 'completed'
      return { ...currentJob, status, crawled_url_count: status === 'queued' ? 0 : 4,
        finished_at: status === 'completed' ? new Date(startedAt + 9000).toISOString() : null,
        checked_items: [...currentJob.checked_items, ...(currentJob.level_id === 'xss' ? [{ id: 'xss', label: '反射型XSS確認（表示例）' }] : [])],
        findings: status !== 'completed' ? [] : [
          ...(currentJob.level_id === 'xss' ? [finding('40012', 'high', '反射型XSSの疑い', 'テスト入力が応答に反映されたという例です。', '入力内容を表示する箇所とエスケープ処理を確認してください。')] : []),
          finding('10038', 'medium', 'CSPヘッダー未設定', 'スクリプトなどの読み込み元を制限する設定がない例です。', '必要な読み込み元を整理し、テスト環境でCSP設定を検討してください。'),
          finding('10035', 'low', 'HSTSヘッダー未設定', 'HTTPS接続を継続して使う設定がない例です。', 'HTTPSが安定して使えることを確認してから導入を検討してください。'),
        ] }
    },
    async cancel(id, signal) {
      await pause(signal)
      if (!currentJob || currentJob.id !== id || Date.now() - startedAt >= 3500) throw new Error('already_running')
      currentJob = { ...currentJob, status: 'cancelled' }
      return { ...currentJob }
    },
  }
}
