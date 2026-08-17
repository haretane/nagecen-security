import { useEffect, useRef, useState } from 'react'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'
const LAST_SCAN_JOB_KEY = 'nagecen_security_last_scan_job_id'
const SCAN_STATUS_LABELS = {
  queued: '開始待ち',
  running: '診断中',
  completed: '完了',
  failed: '失敗',
  cancelled: '中止',
}

const AUTHENTICATION_OPTIONS = [
  { id: 'none', title: 'ログインは必要ありません', description: '誰でも見られるページだけで構成されています。' },
  { id: 'form', title: 'ID・メールアドレスとパスワード', description: 'サイト内の通常のログイン画面を使います。' },
  { id: 'external', title: 'Google・GitHub・Appleなど', description: '外部サービスのアカウントでログインします。' },
  { id: 'special', title: 'その他・分からない', description: '二要素認証など、上記以外の方式です。' },
]

const SERVICE_FEATURE_OPTIONS = [
  { id: 'view_only', label: '見るだけのページ' },
  { id: 'forms_or_posts', label: '入力・お問い合わせ・投稿機能がある' },
  { id: 'login', label: 'ログイン機能がある' },
  { id: 'stores_data', label: '入力内容や利用者のデータを保存する' },
  { id: 'personal_data', label: '名前・メールアドレスなどの個人情報を扱う' },
  { id: 'payments', label: '支払い・決済機能がある' },
  { id: 'unknown', label: 'よく分からない' },
]

function App() {
  const [health, setHealth] = useState({ state: 'loading', message: '接続を確認しています…' })
  const [targetUrl, setTargetUrl] = useState('')
  const [validation, setValidation] = useState({ state: 'idle', message: '' })
  const [verification, setVerification] = useState(null)
  const [verificationStatus, setVerificationStatus] = useState({ state: 'idle', message: '' })
  const [copyLabel, setCopyLabel] = useState('コピー')
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false)
  const [activeScanConfirmed, setActiveScanConfirmed] = useState(false)
  const [dataChangeRiskAcknowledged, setDataChangeRiskAcknowledged] = useState(false)
  const [scanLevels, setScanLevels] = useState([])
  const [selectedLevelId, setSelectedLevelId] = useState('basic')
  const [authenticationType, setAuthenticationType] = useState('none')
  const [serviceFeatures, setServiceFeatures] = useState([])
  const [handoffContext, setHandoffContext] = useState(null)
  const [handoffState, setHandoffState] = useState({ state: 'idle', message: '' })
  const handoffExchangeStarted = useRef(false)
  const [loginUrl, setLoginUrl] = useState('')
  const [loginIdentifier, setLoginIdentifier] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [scanJob, setScanJob] = useState(null)
  const [scanMessage, setScanMessage] = useState('')
  const [overallPromptCopyLabel, setOverallPromptCopyLabel] = useState('プロンプトをコピー')
  const [copiedFindingKey, setCopiedFindingKey] = useState(null)
  const [showOverallPrompt, setShowOverallPrompt] = useState(false)
  const [showImprovementPrompt, setShowImprovementPrompt] = useState(false)
  const [showIndividualPrompts, setShowIndividualPrompts] = useState(false)
  const [expandedFindingKey, setExpandedFindingKey] = useState(null)
  const selectedLevel = scanLevels.find((level) => level.id === selectedLevelId)
  const requiresActiveScanConsent = (selectedLevel?.active_rule_ids.length ?? 0) > 0
  const isNagecenHandoff = window.location.pathname === '/integrations/nagecen'

  useEffect(() => {
    if (window.location.pathname !== '/integrations/nagecen' || handoffExchangeStarted.current) return
    handoffExchangeStarted.current = true
    const token = new URLSearchParams(window.location.search).get('token')
    const endpoint = token
      ? `${API_BASE_URL}/api/integrations/nagecen/handoff-token/exchange`
      : `${API_BASE_URL}/api/integrations/nagecen/session`
    setHandoffState({ state: 'loading', message: 'NAGeCenからの連携情報を確認しています…' })

    fetch(endpoint, {
      method: token ? 'POST' : 'GET',
      headers: token ? { 'Content-Type': 'application/json' } : undefined,
      body: token ? JSON.stringify({ token }) : undefined,
      credentials: 'include',
    })
      .then(async (response) => ({ response, data: await response.json() }))
      .then(({ response, data }) => {
        if (!response.ok) throw new Error(data.detail?.message ?? '連携情報を確認できませんでした。')
        setHandoffContext(data)
        setTargetUrl(data.normalized_url)
        setValidation({ state: 'success', message: 'NAGeCenに登録されたURLを確認しました。' })
        setHandoffState({ state: 'success', message: 'NAGeCenのプロダクト情報を安全に受け取りました。' })
        if (token) window.history.replaceState({}, '', '/integrations/nagecen')
      })
      .catch((error) => setHandoffState({ state: 'error', message: error.message }))
  }, [])

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

  useEffect(() => {
    const controller = new AbortController()
    fetch(`${API_BASE_URL}/api/scan-jobs/levels`, { signal: controller.signal })
      .then((response) => response.ok ? response.json() : [])
      .then(setScanLevels)
      .catch((error) => {
        if (error.name !== 'AbortError') setScanLevels([])
      })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    // NAGeCen連携では、別のプロダクトで行った過去の診断結果を表示しない。
    if (window.location.pathname === '/integrations/nagecen') return
    const lastJobId = window.localStorage.getItem(LAST_SCAN_JOB_KEY)
    if (!lastJobId) return

    const controller = new AbortController()
    async function restoreLastScan() {
      try {
        const response = await fetch(`${API_BASE_URL}/api/scan-jobs/${lastJobId}`, {
          signal: controller.signal,
        })
        if (!response.ok) {
          window.localStorage.removeItem(LAST_SCAN_JOB_KEY)
          return
        }
        const job = await response.json()
        setScanJob(job)
        setScanMessage(
          job.status === 'completed'
            ? `前回の${job.level_display_name}診断結果を表示しています。`
            : job.status === 'failed'
              ? (job.error_message ?? '前回の診断は失敗しました。')
              : '前回開始した診断の状態を確認しています…',
        )
      } catch (error) {
        if (error.name !== 'AbortError') {
          setScanMessage('前回の診断結果を読み込めませんでした。')
        }
      }
    }
    restoreLastScan()
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (!scanJob || !['queued', 'running'].includes(scanJob.status)) return undefined

    const intervalId = window.setInterval(async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/scan-jobs/${scanJob.id}`)
        if (!response.ok) return
        const updatedJob = await response.json()
        setScanJob(updatedJob)
        if (updatedJob.status === 'completed') {
          setScanMessage(`${updatedJob.level_display_name}診断が完了しました。`)
        } else if (updatedJob.status === 'running') {
          setScanMessage('対象ページを巡回して、安全設定を確認しています…')
        } else if (updatedJob.status === 'failed') {
          setScanMessage(updatedJob.error_message ?? '診断処理に失敗しました。')
        }
      } catch {
        // 一時的な通信失敗ではジョブを止めず、次回の確認を待ちます。
      }
    }, 3000)

    return () => window.clearInterval(intervalId)
  }, [scanJob])

  async function handleUrlValidation(event) {
    event.preventDefault()
    setVerification(null)
    setVerificationStatus({ state: 'idle', message: '' })
    setAuthorizationConfirmed(false)
    setActiveScanConfirmed(false)
    setDataChangeRiskAcknowledged(false)
    setAuthenticationType('none')
    setServiceFeatures([])
    setLoginUrl('')
    setLoginIdentifier('')
    setLoginPassword('')
    setScanJob(null)
    setScanMessage('')
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
        credentials: 'include',
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
          code: data.detail?.code,
          message: data.detail?.message ?? '所有確認を完了できませんでした。',
        })
        return
      }

      setVerificationStatus({
        state: 'success',
        message: `${data.target_host} の所有確認が完了しました。`,
      })
      setVerification((current) => ({
        ...current,
        verified_target_id: data.verified_target_id,
        verified_origin: data.verified_origin,
        verified_base_path: data.verified_base_path,
      }))
    } catch {
      setVerificationStatus({ state: 'error', message: '所有確認を完了できませんでした。' })
    }
  }

  async function startPassiveScan() {
    if (!verification?.verified_target_id
      || !authorizationConfirmed
      || (requiresActiveScanConsent && (!activeScanConfirmed || !dataChangeRiskAcknowledged))) return

    setScanMessage('診断ジョブを登録しています…')
    try {
      const response = await fetch(`${API_BASE_URL}/api/scan-jobs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          verified_target_id: verification.verified_target_id,
          level_id: selectedLevelId,
          authorization_confirmed: authorizationConfirmed,
          active_scan_confirmed: requiresActiveScanConsent && activeScanConfirmed,
          data_change_risk_acknowledged: requiresActiveScanConsent && dataChangeRiskAcknowledged,
          authentication_type: authenticationType,
          service_features: serviceFeatures,
          form_authentication: authenticationType === 'form' ? {
            login_url: loginUrl,
            identifier: loginIdentifier,
            password: loginPassword,
          } : null,
        }),
      })
      const data = await response.json()
      if (!response.ok) {
        setScanMessage(data.detail?.message ?? '診断ジョブを登録できませんでした。')
        return
      }
      setScanJob(data)
      setLoginPassword('')
      window.localStorage.setItem(LAST_SCAN_JOB_KEY, data.id)
      setScanMessage('診断の開始を待っています…')
    } catch {
      setScanMessage('診断ジョブを登録できませんでした。')
    }
  }

  async function cancelQueuedScan() {
    if (!scanJob || scanJob.status !== 'queued') return
    setScanMessage('診断の中止を確認しています…')
    try {
      const response = await fetch(`${API_BASE_URL}/api/scan-jobs/${scanJob.id}/cancel`, {
        method: 'POST',
      })
      const data = await response.json()
      if (!response.ok) {
        setScanMessage(data.detail?.message ?? '診断を中止できませんでした。')
        return
      }
      setScanJob(data)
      setScanMessage('診断を開始前に中止しました。')
      window.localStorage.removeItem(LAST_SCAN_JOB_KEY)
    } catch {
      setScanMessage('診断を中止できませんでした。')
    }
  }

  function prepareRescan() {
    setScanJob(null)
    setScanMessage('')
    setAuthorizationConfirmed(false)
    setActiveScanConfirmed(false)
    setDataChangeRiskAcknowledged(false)
    window.localStorage.removeItem(LAST_SCAN_JOB_KEY)
  }

  async function copyOverallPrompt(prompt) {
    if (!prompt) return
    try {
      await navigator.clipboard.writeText(prompt)
      setOverallPromptCopyLabel('コピーしました')
      window.setTimeout(
        () => setOverallPromptCopyLabel('プロンプトをコピー'),
        1800,
      )
    } catch {
      setOverallPromptCopyLabel('コピーできませんでした')
    }
  }

  async function copyFindingPrompt(finding, key) {
    try {
      await navigator.clipboard.writeText(finding.ai_prompt)
      setCopiedFindingKey(key)
      window.setTimeout(() => setCopiedFindingKey(null), 1800)
    } catch {
      setCopiedFindingKey(`error-${key}`)
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
        {handoffState.state !== 'idle' && (
          <section className={`handoff-banner handoff-${handoffState.state}`} role="status">
            <strong>NAGeCenからのSecurity確認</strong>
            <p>{handoffState.message}</p>
            {handoffContext && <small>対象プロダクトID：{handoffContext.product_id}</small>}
          </section>
        )}
        <section className="hero">
          <p className="eyebrow">SECURITY CHECK FOR BEGINNERS</p>
          <h1>つくったサービスに、<br />安心して公開するための確認を。</h1>
          <p className="lead">
            NAGeCen Securityは、Webサービスの安全性を初心者にも分かりやすく確認するための付随サービスです。
          </p>

          <form className="url-check-card" onSubmit={handleUrlValidation}>
            {isNagecenHandoff ? (
              <div className="handoff-target-summary">
                <strong>今回確認するプロダクト</strong>
                {handoffContext ? (
                  <>
                    <p>NAGeCenの登録画面で入力されたURLを受け取りました。</p>
                    <code>{handoffContext.normalized_url}</code>
                    <small>安全のため、この画面では別のURLへ変更できません。</small>
                  </>
                ) : (
                  <p>{handoffState.message || 'NAGeCenからプロダクト情報を受け取っています…'}</p>
                )}
              </div>
            ) : (
              <>
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
                      setAuthorizationConfirmed(false)
                      setActiveScanConfirmed(false)
                      setDataChangeRiskAcknowledged(false)
                      setAuthenticationType('none')
                      setLoginUrl('')
                      setLoginIdentifier('')
                      setLoginPassword('')
                      setScanJob(null)
                      setScanMessage('')
                    }}
                    maxLength={2048}
                    required
                  />
                  <button type="submit" disabled={validation.state === 'loading'}>
                    {validation.state === 'loading' ? '確認中…' : 'URLを確認'}
                  </button>
                </div>
              </>
            )}
            {validation.state !== 'idle' && !isNagecenHandoff && (
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
                {isNagecenHandoff ? '所有確認へ進む' : '所有確認キーを発行'}
              </button>
            )}

            {verification && (
              <section className="verification-panel" aria-labelledby="verification-title">
                <div className="step-label">STEP 2</div>
                <h2 id="verification-title">対象サイトへ確認タグを設置</h2>
                <div className="verification-explanation">
                  <strong>なぜ確認タグが必要なのですか？</strong>
                  <p>
                    このプロダクトを自分で管理しているか、管理者から掲載・診断の許可を
                    受けていることを確認する（本人以外の所有物でないかを確認する）ためです。開発コードの中へ一時的な確認用タグを
                    設置し、NAGeCen Securityがそのタグを見つけられるか確認します。
                  </p>
                  <p>
                    このタグが画面に表示されたり、サイトの機能を変更したりすることはありません。
                    所有確認が完了した後は削除して問題ありません。
                  </p>
                </div>
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
              <div
                className={`verification-status verification-${verificationStatus.state}`}
                role="status"
                aria-live="polite"
              >
                <p>{verificationStatus.message}</p>
                {verificationStatus.code === 'meta_not_found' && (
                  <div className="verification-error-help">
                    <strong>タグを追加した直後の場合</strong>
                    <p>
                      タグを追加して更新したのち、Web上のページへ変更が反映されるまで
                      数分かかる場合があります。少し待ってからもう一度お試しください。
                    </p>
                  </div>
                )}
              </div>
            )}

            {verificationStatus.state === 'success' && (
              <section className="scan-start-panel" aria-labelledby="scan-start-title">
                {handoffContext?.intent === 'verify_only' && (
                  <div className="handoff-return-panel">
                    <strong>所有確認が完了しました</strong>
                    <p>診断を行わず、NAGeCenの登録画面へ戻れます。</p>
                    <a href={handoffContext.return_url}>NAGeCenへ戻る</a>
                  </div>
                )}
                {handoffContext?.intent !== 'verify_only' && (
                  <>
                <div className="step-label">STEP 3</div>
                <h2>このサービスに当てはまるものはありますか？</h2>
                <p>診断結果の優先順位を調整するために使います。分かる範囲で選んでください。</p>
                <div className="service-feature-selector">
                  {SERVICE_FEATURE_OPTIONS.map((option) => (
                    <label className="service-feature-option" key={option.id}>
                      <input
                        type="checkbox"
                        checked={serviceFeatures.includes(option.id)}
                        disabled={scanJob !== null}
                        onChange={(event) => {
                          setServiceFeatures((current) => {
                            if (['unknown', 'view_only'].includes(option.id)) return event.target.checked ? [option.id] : []
                            const withoutUnknown = current.filter((item) => !['unknown', 'view_only'].includes(item))
                            return event.target.checked
                              ? [...withoutUnknown, option.id]
                              : withoutUnknown.filter((item) => item !== option.id)
                          })
                        }}
                      />
                      <span>{option.label}</span>
                    </label>
                  ))}
                </div>

                <div className="step-label questionnaire-step">STEP 4</div>
                <h2>ログインが必要なページはありますか？</h2>
                <p>
                  ログインしないと見られないページがある場合は、使っているログイン方式を選んでください。
                </p>
                <div className="authentication-selector">
                  {AUTHENTICATION_OPTIONS.map((option) => (
                    <label
                      className={`authentication-option ${authenticationType === option.id ? 'authentication-selected' : ''}`}
                      key={option.id}
                    >
                      <input
                        type="radio"
                        name="authentication-type"
                        value={option.id}
                        checked={authenticationType === option.id}
                        onChange={() => {
                          setAuthenticationType(option.id)
                          if (option.id !== 'form') {
                            setLoginUrl('')
                            setLoginIdentifier('')
                            setLoginPassword('')
                          }
                        }}
                        disabled={scanJob !== null}
                      />
                      <span><strong>{option.title}</strong><small>{option.description}</small></span>
                    </label>
                  ))}
                </div>
                {authenticationType === 'form' && (
                  <div className="form-authentication-panel">
                    <p className="authentication-notice">
                      診断専用のテストアカウントを入力してください。本物の個人アカウントは使用しないでください。
                      ログイン画面を自動操作し、成功を確認できた場合だけログイン後のページも巡回します。
                      対応できない画面では、公開ページだけ診断を続けます。
                    </p>
                    <label htmlFor="login-url">ログイン画面のURL</label>
                    <input
                      id="login-url"
                      type="url"
                      inputMode="url"
                      autoComplete="off"
                      placeholder={`${targetUrl.replace(/\/$/, '')}/login`}
                      value={loginUrl}
                      onChange={(event) => setLoginUrl(event.target.value)}
                      disabled={scanJob !== null}
                      maxLength={2048}
                      required
                    />
                    <label htmlFor="login-identifier">IDまたはメールアドレス</label>
                    <input
                      id="login-identifier"
                      type="text"
                      autoComplete="off"
                      value={loginIdentifier}
                      onChange={(event) => setLoginIdentifier(event.target.value)}
                      disabled={scanJob !== null}
                      maxLength={320}
                      required
                    />
                    <label htmlFor="login-password">パスワード</label>
                    <input
                      id="login-password"
                      type="password"
                      autoComplete="off"
                      value={loginPassword}
                      onChange={(event) => setLoginPassword(event.target.value)}
                      disabled={scanJob !== null}
                      maxLength={1024}
                      required
                    />
                    <small>
                      パスワードはPostgreSQLへ保存せず、15分以内またはWorkerが受け取った時点で削除します。
                    </small>
                  </div>
                )}
                {['external', 'special'].includes(authenticationType) && (
                  <div className="authentication-notice authentication-unsupported">
                    このログイン方式はMVPでは対象外です。ログイン後のページは確認せず、
                    ログインなしで見られる範囲の診断を続けます。
                  </div>
                )}

                <div className="step-label scan-level-step">STEP 5</div>
                <h2 id="scan-start-title">診断レベルを選択</h2>
                <div className="level-selector">
                  {scanLevels.map((level) => (
                    <label className={`level-option ${selectedLevelId === level.id ? 'level-selected' : ''}`} key={level.id}>
                      <input
                        type="radio"
                        name="scan-level"
                        value={level.id}
                        checked={selectedLevelId === level.id}
                        onChange={() => {
                          setSelectedLevelId(level.id)
                          setActiveScanConfirmed(false)
                          setDataChangeRiskAcknowledged(false)
                        }}
                        disabled={scanJob !== null || !level.available}
                      />
                      <span>
                        <strong>{level.display_name}</strong>{level.description}
                        <small>{level.price_label}</small>
                      </span>
                    </label>
                  ))}
                </div>
                <p>
                  ページを自動で見て回り（Spider）、通信内容から安全設定を確認します
                  （パッシブ診断）。
                </p>
                {selectedLevelId === 'basic' && (
                  <p className="advanced-description">
                    Lv.1では入力欄へのテスト文字の送信は行わないため、XSSは診断しません。
                    結果画面から、制作を補助したAIへコード確認を依頼する方法をご案内する予定です。
                  </p>
                )}
                {selectedLevelId === 'xss' && (
                  <p className="advanced-description">
                    Lv.2では、Lv.1の内容に反射型XSSの確認を追加します。入力欄へテスト文字を
                    自動送信します（反射型XSSのActive Scan）。
                  </p>
                )}
                {selectedLevelId === 'advanced' && (
                  <p className="advanced-description">
                    Lv.3では、Lv.2の内容にSQLインジェクション、OSコマンドインジェクション、
                    パストラバーサルの確認を追加します（有料化予定）。
                  </p>
                )}
                <div className="scan-caution">
                  <strong>開始前にご確認ください</strong>
                  <ul>
                    <li>診断ツールがページを自動で開くため、短時間に複数回アクセスします（Spiderによる巡回）。</li>
                    {requiresActiveScanConsent && (
                      <>
                        <li>入力欄がある場合、安全性を調べるテスト文字を自動送信します（Active Scan）。</li>
                        <li>お問い合わせではテストメール、投稿・会員登録では仮データが残る可能性があります。</li>
                        <li>NAGeCenへ登録するURLで、発生したテストデータを確認・削除できる状態で実行してください。</li>
                      </>
                    )}
                  </ul>
                </div>
                <label className="authorization-check">
                  <input
                    type="checkbox"
                    checked={authorizationConfirmed}
                    onChange={(event) => setAuthorizationConfirmed(event.target.checked)}
                    disabled={scanJob !== null}
                  />
                  <span className="checkbox-visual" aria-hidden="true">
                    <svg viewBox="0 0 20 20" focusable="false">
                      <path d="M4 10.5 8.2 15 16 5.5" />
                    </svg>
                  </span>
                  <span>このサイトは自分で管理しているか、管理者から診断の許可をもらっています。</span>
                </label>
                {requiresActiveScanConsent && (
                  <>
                    <label className="authorization-check">
                      <input
                        type="checkbox"
                        checked={activeScanConfirmed}
                        onChange={(event) => setActiveScanConfirmed(event.target.checked)}
                        disabled={scanJob !== null}
                      />
                      <span className="checkbox-visual" aria-hidden="true">
                        <svg viewBox="0 0 20 20" focusable="false"><path d="M4 10.5 8.2 15 16 5.5" /></svg>
                      </span>
                      <span>診断ツールが入力欄へテスト文字を入れ、自動送信することを確認しました（Active Scan）。</span>
                    </label>
                    <label className="authorization-check">
                      <input
                        type="checkbox"
                        checked={dataChangeRiskAcknowledged}
                        onChange={(event) => setDataChangeRiskAcknowledged(event.target.checked)}
                        disabled={scanJob !== null}
                      />
                      <span className="checkbox-visual" aria-hidden="true">
                        <svg viewBox="0 0 20 20" focusable="false"><path d="M4 10.5 8.2 15 16 5.5" /></svg>
                      </span>
                      <span>テストメールが送られたり、テスト投稿や仮データが残ったりする可能性を確認しました。</span>
                    </label>
                  </>
                )}
                <button
                  className="scan-start-button"
                  type="button"
                  onClick={startPassiveScan}
                  disabled={!selectedLevel?.available
                    || serviceFeatures.length === 0
                    || !authorizationConfirmed
                    || (authenticationType === 'form'
                      && (!loginUrl || !loginIdentifier || !loginPassword))
                    || (requiresActiveScanConsent && (!activeScanConfirmed || !dataChangeRiskAcknowledged))
                    || scanJob !== null}
                >
                  {selectedLevel?.display_name ?? '選択したレベル'} 診断を開始
                </button>
                  </>
                )}
              </section>
            )}

            {scanJob && (
              <section className={`scan-progress scan-${scanJob.status}`} aria-live="polite">
                <div>
                  <strong>{scanJob.level_display_name} 診断</strong>
                  <span className="scan-status-label">
                    {SCAN_STATUS_LABELS[scanJob.status] ?? scanJob.status}
                  </span>
                </div>
                <p>{scanMessage}</p>
                {['queued', 'running'].includes(scanJob.status) && (
                  <div className="scan-waiting-note" role="status">
                    <span>この診断には数分かかる場合があります</span>
                    <span className="loading-dots" aria-hidden="true">
                      <i />
                      <i />
                      <i />
                    </span>
                    <small>今回チェックできた項目は、診断完了後に表示します。</small>
                  </div>
                )}
                {scanJob.status === 'queued' && (
                  <button className="scan-cancel-button" type="button" onClick={cancelQueuedScan}>
                    開始前の診断を中止
                  </button>
                )}
                {['failed', 'cancelled'].includes(scanJob.status) && (
                  <div className="scan-recovery-panel">
                    <strong>{scanJob.status === 'failed' ? '診断を完了できませんでした' : '診断を中止しました'}</strong>
                    <p>
                      {handoffContext
                        ? 'NAGeCenへ戻り、同じプロダクトから改めて診断を開始できます。'
                        : '所有確認はそのまま利用して、もう一度診断できます。'}
                    </p>
                    {handoffContext ? (
                      <a href={handoffContext.return_url}>NAGeCenへ戻る</a>
                    ) : (
                      <button type="button" onClick={prepareRescan}>もう一度診断する</button>
                    )}
                  </div>
                )}
                {scanJob.status === 'completed' && (
                  <div className="scan-result">
                    <dl className="scan-summary">
                      <div><dt>巡回URL数</dt><dd>{scanJob.crawled_url_count}</dd></div>
                      <div><dt>要注意の改善点</dt><dd>{scanJob.findings.filter((item) => item.presentation_group === 'attention').length}</dd></div>
                      <div><dt>改善候補</dt><dd>{scanJob.findings.filter((item) => item.presentation_group === 'improvement').length}</dd></div>
                    </dl>

                    <section className="authentication-result" aria-labelledby="authentication-result-title">
                      <h3 id="authentication-result-title">ログイン後ページの確認</h3>
                      <p>{scanJob.authentication_message}</p>
                    </section>

                    <section className="check-result" aria-labelledby="checked-title">
                      <h3 id="checked-title">今回チェックした項目</h3>
                      <ul className="check-list checked-list">
                        {scanJob.checked_items.map((item) => <li key={item.id}>{item.label}</li>)}
                      </ul>
                    </section>

                    <section className="check-result" aria-labelledby="unchecked-title">
                      <h3 id="unchecked-title">今回チェックしていない項目</h3>
                      <p className="check-result-help">次の項目は、選択したレベルより上で確認します。</p>
                      {scanJob.unchecked_items.length > 0 ? (
                        <ul className="check-list unchecked-list">
                          {scanJob.unchecked_items.map((item) => <li key={item.id}>{item.label}</li>)}
                        </ul>
                      ) : (
                        <p className="all-checked-message">このレベルより上で追加予定の項目はありません。</p>
                      )}
                    </section>

                    {scanJob.level_id === 'basic' && (
                      <section className="xss-guidance" aria-labelledby="xss-guidance-title">
                        <div className="xss-guidance-heading">
                          <span aria-hidden="true">!</span>
                          <h3 id="xss-guidance-title">XSSは今回のLv.1では診断していません</h3>
                        </div>
                        <p>
                          XSS（クロスサイトスクリプティング）を自動で詳しく調べるには、入力欄へ
                          テスト文字を送信する必要があります。初心者向けのLv.1ではサイトへの影響を
                          避けるため、この操作を行いません。
                        </p>
                        <p>
                          制作を補助したAIがソースコードを確認できる場合は、次のプロンプトを渡して
                          XSS対策の確認を依頼してください。
                        </p>
                        <small>
                          XSS対策の確認依頼は、下にある全体の相談用プロンプトへ含まれています。
                        </small>
                      </section>
                    )}

                    {scanJob.incomplete_items.length > 0 && (
                      <section className="check-result incomplete-result" aria-labelledby="incomplete-title">
                        <h3 id="incomplete-title">完了できなかった項目</h3>
                        <p className="check-result-help">
                          今回のレベルで予定していましたが、失敗または時間切れで完了できなかった項目です。
                        </p>
                        <ul className="check-list incomplete-list">
                          {scanJob.incomplete_items.map((item) => <li key={item.id}>{item.label}</li>)}
                        </ul>
                      </section>
                    )}

                    <section className="findings" aria-labelledby="findings-title">
                      <div className="findings-heading">
                        <h3 id="findings-title">要注意の改善点</h3>
                        <span>{scanJob.findings.filter((item) => item.presentation_group === 'attention').length}件</span>
                      </div>
                      <p className="finding-group-help">
                        安全に公開・運用するため、優先して確認したい項目です。
                      </p>
                      {scanJob.findings.filter((item) => item.presentation_group === 'attention').length === 0 ? (
                        <p className="no-findings">今回の診断では、優先して確認する項目は見つかりませんでした。</p>
                      ) : (
                        <div className="finding-list">
                          {scanJob.findings.filter((item) => item.presentation_group === 'attention').map((finding, findingIndex) => {
                            const findingKey = `${finding.rule_id}-${finding.title}-${findingIndex}`
                            return (
                            <article className="finding-card" key={findingKey}>
                              <div className="finding-title-row">
                                <span className={`risk-badge risk-${finding.risk}`}>
                                  {finding.priority_label}（重要度：{finding.risk_label}）
                                </span>
                                <span className="location-count">{finding.location_count}箇所</span>
                              </div>
                              <h4>{finding.title}</h4>
                              <p>{finding.description}</p>
                              <div className="finding-solution">
                                <strong>対応の方向性</strong>
                                <p>{finding.solution}</p>
                              </div>
                              <details>
                                <summary>技術情報と該当URLを確認する</summary>
                                <p className="technical-title">ZAPでの名称：{finding.technical_title}</p>
                                <ul>
                                  {finding.locations.map((location, index) => (
                                    <li key={`${location.url}-${location.parameter}-${index}`}>
                                      <code>{location.url}</code>
                                      {location.parameter && <small>対象：{location.parameter}</small>}
                                    </li>
                                  ))}
                                </ul>
                              </details>
                            </article>
                            )
                          })}
                        </div>
                      )}
                    </section>

                    {scanJob.findings.some((item) => item.presentation_group === 'improvement') && (
                      <section className="findings findings-improvement" aria-labelledby="improvement-title">
                        <div className="findings-heading">
                          <h3 id="improvement-title">より安全にするための改善候補</h3>
                          <span>{scanJob.findings.filter((item) => item.presentation_group === 'improvement').length}件</span>
                        </div>
                        <p className="finding-group-help">
                          すぐに問題が起きると決まったものではありません。サービスの作り方や公開方法によって、対応が不要な場合や設定できない場合もあります。
                        </p>
                        <div className="finding-list">
                          {scanJob.findings.filter((item) => item.presentation_group === 'improvement').map((finding, findingIndex) => (
                            <article className="finding-card" key={`improvement-${finding.rule_id}-${findingIndex}`}>
                              <div className="finding-title-row"><span className="risk-badge risk-improvement">改善候補</span><span className="location-count">{finding.location_count}箇所</span></div>
                              <h4>{finding.title}</h4><p>{finding.description}</p>
                              <div className="finding-solution"><strong>対応の方向性</strong><p>{finding.solution}</p></div>
                              <details><summary>技術情報と該当URLを確認する</summary><p className="technical-title">ZAPでの名称：{finding.technical_title}</p></details>
                            </article>
                          ))}
                        </div>
                      </section>
                    )}

                    {scanJob.findings.some((item) => item.presentation_group === 'reference') && (
                      <details className="reference-findings">
                        <summary>診断時の参考情報（{scanJob.findings.filter((item) => item.presentation_group === 'reference').length}件）</summary>
                        <p>問題が見つかったという意味ではなく、今回の診断範囲を理解するための情報です。</p>
                        <ul>{scanJob.findings.filter((item) => item.presentation_group === 'reference').map((finding, index) => <li key={`reference-${finding.rule_id}-${index}`}>{finding.title}</li>)}</ul>
                      </details>
                    )}

                    <section className="ai-consultation" aria-labelledby="ai-prompt-title">
                        <h3 id="ai-prompt-title">
                          {scanJob.findings.some((item) => item.presentation_group === 'attention') ? '要注意の改善点をAIへ相談する' : '診断結果についてAIへ相談する'}
                        </h3>
                        <p>
                          {scanJob.findings.some((item) => item.presentation_group === 'attention')
                            ? '対応が必要かどうかは、サービスの作り方によって異なります。まずはAIにまとめて相談してみましょう。'
                            : '今回チェックしていない範囲も含めて、追加で確認する内容をAIへ相談できます。'}
                        </p>
                        <p className="ai-consultation-guide">
                          プロダクトの開発や修正について相談できるAIへ、この文章を貼り付けてください。
                          AIが開発内容を確認できない場合は、使用しているサービスや開発方法、
                          必要なコードなどを追加で伝えてください。
                        </p>
                        <button
                          type="button"
                          aria-expanded={showOverallPrompt}
                          onClick={() => setShowOverallPrompt((current) => !current)}
                        >
                          {showOverallPrompt ? '全体プロンプトを閉じる' : '全体の修正相談用プロンプトを確認'}
                        </button>
                        <small>AIには、修正が必要かどうかの確認も依頼します。</small>
                        {showOverallPrompt && (
                          <div className="prompt-preview">
                            <pre>{scanJob.attention_ai_prompt}</pre>
                            <button type="button" onClick={() => copyOverallPrompt(scanJob.attention_ai_prompt)}>{overallPromptCopyLabel}</button>
                          </div>
                        )}

                        {scanJob.improvement_ai_prompt && (
                          <div className="improvement-prompt-action">
                            <button type="button" aria-expanded={showImprovementPrompt} onClick={() => setShowImprovementPrompt((current) => !current)}>
                              {showImprovementPrompt ? '改善候補のプロンプトを閉じる' : '改善候補をまとめてAIへ相談する'}
                            </button>
                            {showImprovementPrompt && <div className="prompt-preview"><pre>{scanJob.improvement_ai_prompt}</pre><button type="button" onClick={() => copyOverallPrompt(scanJob.improvement_ai_prompt)}>{overallPromptCopyLabel}</button></div>}
                          </div>
                        )}

                        {scanJob.findings.some((item) => item.presentation_group !== 'reference') && <div className="individual-prompt-section">
                          <button
                            type="button"
                            className="individual-prompt-toggle"
                            aria-expanded={showIndividualPrompts}
                            onClick={() => setShowIndividualPrompts((current) => !current)}
                          >
                            {showIndividualPrompts
                              ? '問題ごとのプロンプトを閉じる'
                              : '問題ごとの個別相談用プロンプトを確認'}
                          </button>
                          {showIndividualPrompts && (
                            <div className="individual-prompt-list">
                              <p>特定の問題だけを詳しく相談したい場合に使用します。</p>
                              {scanJob.findings.filter((item) => item.presentation_group !== 'reference').map((finding, findingIndex) => {
                                const findingKey = `${finding.rule_id}-${finding.title}-${findingIndex}`
                                return (
                                  <section key={findingKey} className="individual-prompt-item">
                                    <strong>{finding.title}</strong>
                                    <button
                                      type="button"
                                      aria-expanded={expandedFindingKey === findingKey}
                                      onClick={() => setExpandedFindingKey(
                                        expandedFindingKey === findingKey ? null : findingKey,
                                      )}
                                    >
                                      {expandedFindingKey === findingKey ? '閉じる' : 'この項目だけAIに相談する'}
                                    </button>
                                    {expandedFindingKey === findingKey && (
                                      <div className="prompt-preview finding-prompt-preview">
                                        <pre>{finding.ai_prompt}</pre>
                                        <button type="button" onClick={() => copyFindingPrompt(finding, findingKey)}>
                                          {copiedFindingKey === findingKey
                                            ? 'コピーしました'
                                            : copiedFindingKey === `error-${findingKey}`
                                              ? 'コピーできませんでした'
                                              : 'プロンプトをコピー'}
                                        </button>
                                      </div>
                                    )}
                                  </section>
                                )
                              })}
                            </div>
                          )}
                        </div>}
                      </section>

                    {handoffContext && (
                      <section className="handoff-return-panel" aria-labelledby="handoff-return-title">
                        <h3 id="handoff-return-title">
                          {scanJob.findings.some((item) => item.presentation_group !== 'reference')
                            ? '修正してから、もう一度診断するには'
                            : '診断結果を確認しました'}
                        </h3>
                        {scanJob.findings.some((item) => item.presentation_group !== 'reference') ? (
                          <>
                            <p>次の流れで修正と再診断ができます。</p>
                            <ol>
                              <li>上に表示された問題の説明を確認します。</li>
                              <li>必要に応じてAI相談用プロンプトをコピーし、開発に使っているAIへ渡します。</li>
                              <li>開発コードを修正し、Web上のサービスを更新します。</li>
                              <li>NAGeCenへ戻り、登録画面からもう一度セキュリティ診断を行います。</li>
                            </ol>
                          </>
                        ) : (
                          <p>NAGeCenへ戻り、プロダクト登録または編集を続けられます。</p>
                        )}
                        <p className="handoff-result-note">
                          今回の診断結果はNAGeCenへ通知されます。
                        </p>
                        <a href={handoffContext.return_url}>
                          NAGeCenへ戻って{handoffContext.return_context_type === 'product_draft' ? '登録を続ける' : '編集を続ける'}
                        </a>
                      </section>
                    )}
                  </div>
                )}
              </section>
            )}
          </form>

          <div className={`status-card status-${health.state}`} role="status" aria-live="polite">
            <span className="status-indicator" aria-hidden="true" />
            <div>
              <strong>{health.message}</strong>
              <p>URLの安全確認、所有確認、Lv.1基本セーフティチェックを利用できます。</p>
            </div>
          </div>
        </section>
      </main>

      <footer>NAGeCen Security — a companion service for NAGeCen</footer>
    </div>
  )
}

export default App
