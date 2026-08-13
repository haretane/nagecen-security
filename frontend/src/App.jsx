import { useEffect, useState } from 'react'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

function App() {
  const [health, setHealth] = useState({ state: 'loading', message: '接続を確認しています…' })
  const [targetUrl, setTargetUrl] = useState('')
  const [validation, setValidation] = useState({ state: 'idle', message: '' })
  const [verification, setVerification] = useState(null)
  const [verificationStatus, setVerificationStatus] = useState({ state: 'idle', message: '' })
  const [copyLabel, setCopyLabel] = useState('コピー')

  useEffect(() => {
    const controller = new AbortController()

    async function checkHealth() {
      try {
        const response = await fetch(`${API_BASE_URL}/health`, {
          signal: controller.signal,
        })

        if (!response.ok) {
          throw new Error('Health check failed')
        }

        const data = await response.json()
        const isHealthy = data.status === 'ok' && data.database === 'connected'

        setHealth(
          isHealthy
            ? { state: 'success', message: '開発環境は正常です' }
            : { state: 'error', message: 'データベースへ接続できません' },
        )
      } catch (error) {
        if (error.name !== 'AbortError') {
          setHealth({ state: 'error', message: 'バックエンドAPIへ接続できません' })
        }
      }
    }

    checkHealth()

    return () => controller.abort()
  }, [])

  async function handleUrlValidation(event) {
    event.preventDefault()
    setVerification(null)
    setVerificationStatus({ state: 'idle', message: '' })
    setValidation({ state: 'loading', message: 'URLの安全性を確認しています…' })

    try {
      const response = await fetch(`${API_BASE_URL}/api/url-validation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl }),
      })
      const data = await response.json()

      if (!response.ok) {
        const message = data.detail?.message ?? 'URLを確認できませんでした。'
        setValidation({ state: 'error', message })
        return
      }

      setTargetUrl(data.normalized_url)
      setValidation({
        state: 'success',
        message: `公開URLとして確認できました：${data.hostname}`,
      })
    } catch {
      setValidation({
        state: 'error',
        message: 'バックエンドAPIへ接続できません。しばらくしてからお試しください。',
      })
    }
  }

  async function createVerification() {
    setVerificationStatus({ state: 'loading', message: '確認キーを発行しています…' })

    try {
      const response = await fetch(`${API_BASE_URL}/api/site-verifications`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl }),
      })
      const data = await response.json()

      if (!response.ok) {
        setVerificationStatus({
          state: 'error',
          message: data.detail?.message ?? '確認キーを発行できませんでした。',
        })
        return
      }

      setVerification(data)
      setVerificationStatus({
        state: 'ready',
        message: 'metaタグを対象ページの<head>内へ追加してください。',
      })
    } catch {
      setVerificationStatus({ state: 'error', message: '確認キーを発行できませんでした。' })
    }
  }

  async function copyMetaTag() {
    if (!verification) return

    try {
      await navigator.clipboard.writeText(verification.meta_tag)
      setCopyLabel('コピーしました')
      window.setTimeout(() => setCopyLabel('コピー'), 1800)
    } catch {
      setCopyLabel('コピーできませんでした')
    }
  }

  async function confirmVerification() {
    if (!verification) return

    setVerificationStatus({ state: 'loading', message: '対象ページのmetaタグを確認しています…' })

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/site-verifications/${verification.verification_id}/confirm`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: verification.token }),
        },
      )
      const data = await response.json()

      if (!response.ok) {
        setVerificationStatus({
          state: 'error',
          message: data.detail?.message ?? '所有確認を完了できませんでした。',
        })
        return
      }

      setVerificationStatus({
        state: 'success',
        message: `${data.target_host} の所有確認が完了しました。`,
      })
    } catch {
      setVerificationStatus({ state: 'error', message: '所有確認を完了できませんでした。' })
    }
  }

  return (
    <div className="app-shell">
      <header className="site-header">
        <div className="site-header-inner">
          <a className="brand" href="/" aria-label="NAGeCen Security ホーム">
            <span className="brand-mark" aria-hidden="true">N</span>
            <span>
              <strong>NAGeCen</strong>
              <small>Security</small>
            </span>
          </a>
          <span className="mvp-badge">MVP DEVELOPMENT</span>
        </div>
      </header>

      <main>
        <section className="hero">
          <p className="eyebrow">SECURITY CHECK FOR BEGINNERS</p>
          <h1>つくったサービスに、<br />安心して公開するための確認を。</h1>
          <p className="lead">
            NAGeCen Securityは、Webサービスの安全性を初心者にも分かりやすく確認するための付随サービスです。
          </p>

          <form className="url-check-card" onSubmit={handleUrlValidation}>
            <label htmlFor="target-url">確認したいWebサービスのURL</label>
            <p className="field-help">公開中のトップページURLを、https://から入力してください。</p>
            <div className="url-input-row">
              <input
                id="target-url"
                name="target-url"
                type="url"
                inputMode="url"
                placeholder="https://example.com"
                value={targetUrl}
                onChange={(event) => {
                  setTargetUrl(event.target.value)
                  setValidation({ state: 'idle', message: '' })
                  setVerification(null)
                  setVerificationStatus({ state: 'idle', message: '' })
                }}
                maxLength={2048}
                required
              />
              <button type="submit" disabled={validation.state === 'loading'}>
                {validation.state === 'loading' ? '確認中…' : 'URLを確認'}
              </button>
            </div>
            {validation.state !== 'idle' && (
              <p
                className={`validation-message validation-${validation.state}`}
                role="status"
                aria-live="polite"
              >
                {validation.message}
              </p>
            )}

            {validation.state === 'success' && !verification && (
              <button className="verification-start-button" type="button" onClick={createVerification}>
                所有確認キーを発行
              </button>
            )}

            {verification && (
              <section className="verification-panel" aria-labelledby="verification-title">
                <div className="step-label">STEP 2</div>
                <h2 id="verification-title">対象サイトへ確認タグを設置</h2>
                <p>次の1行を、対象ページのHTMLにある <code>&lt;head&gt;</code> 内へ追加してください。</p>
                <div className="code-copy-row">
                  <code>{verification.meta_tag}</code>
                  <button type="button" onClick={copyMetaTag}>{copyLabel}</button>
                </div>
                <p className="expiry-note">
                  確認キーの有効期限：{new Date(verification.expires_at).toLocaleString('ja-JP')}
                </p>
                <button
                  className="verification-confirm-button"
                  type="button"
                  onClick={confirmVerification}
                  disabled={verificationStatus.state === 'loading' || verificationStatus.state === 'success'}
                >
                  {verificationStatus.state === 'loading' ? '確認中…' : '設置したmetaタグを確認'}
                </button>
              </section>
            )}

            {verificationStatus.state !== 'idle' && (
              <p
                className={`verification-status verification-${verificationStatus.state}`}
                role="status"
                aria-live="polite"
              >
                {verificationStatus.message}
              </p>
            )}
          </form>

          <div className={`status-card status-${health.state}`} role="status" aria-live="polite">
            <span className="status-indicator" aria-hidden="true" />
            <div>
              <strong>{health.message}</strong>
              <p>現在はURLの安全確認まで利用できます。診断機能はまだ実装されていません。</p>
            </div>
          </div>
        </section>
      </main>

      <footer>NAGeCen Security — a companion service for NAGeCen</footer>
    </div>
  )
}

export default App
