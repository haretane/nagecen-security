import { useEffect, useRef, useState } from 'react'
import { AccountShell } from './account-login/AccountViews.jsx'
import testArtwork from './assets/landing/step-01-test.png'
import tagArtwork from './assets/landing/step-02-tag.png'
import DiagnosticProgressPreview from './DiagnosticProgressPreview.jsx'
import './diagnostic-wizard-preview.css'

const steps = ['テスト用環境を準備', 'テスト用URLを入力', '確認タグを設置', '診断内容を選択', '実行前の確認']
// Available basic/xss scopes match backend/app/scans/levels.py; planned scopes
// are presentation-only and cannot be selected. No API calls or jobs.
const diagnosticOptions = [
  { id: 'basic', label: '基本チェック', level: 'Lv.1', description: 'ページを巡回して、通信やCookieなどの設定に改善候補がないか確認します。', checks: ['ブラウザに伝えるセキュリティ設定', 'Cookieの設定', 'HTTPSページ内のHTTP読み込み', '応答に含まれる情報の露出'], note: '攻撃を模した入力テストは行いません。ただし、巡回によってサイトの処理が動く場合があります。', available: true },
  { id: 'xss', label: 'XSS確認を追加する', level: '', description: '入力内容から不正なスクリプトが動く問題を確認します。現在は反射型XSSのみが対象です。', checks: [], coverage: [
    { name: '反射型XSS', detail: '入力内容が、その場で返されるページに反映される仕組み', status: '対応', available: true },
    { name: '保存型XSS', detail: '投稿・コメントなど、保存した内容が後で表示される仕組み', status: '準備中', available: false },
    { name: 'DOM型XSS', detail: 'ブラウザ内のJavaScriptによって、入力内容がページに組み込まれる仕組み', status: '準備中', available: false },
  ], note: 'テスト用の入力・リクエストを送ります。保存型・DOM型XSSとSQLインジェクションの診断は行いません。', available: true },
  { id: 'sql-injection', label: 'SQLインジェクション確認', level: '', description: 'Webサービスへの入力を通じて、データベースに不正な命令を実行させられる問題を確認します。', checks: [], note: '準備中のため選択できません。DBに直接接続して設定を調べる診断ではありません。', available: false },
]
const previewTag = '<meta name="nagecen-security-verification" content="PREVIEW-NOT-A-VALID-TOKEN">'

export default function DiagnosticWizardPreview({ startAtOptions = false, initialUrl = 'https://test.example.com/' }) {
  const [step, setStep] = useState(startAtOptions ? 3 : 0)
  const [ready, setReady] = useState(startAtOptions)
  const [url, setUrl] = useState(startAtOptions ? initialUrl : '')
  const [draftUrl, setDraftUrl] = useState(startAtOptions ? initialUrl : '')
  const [editingUrl, setEditingUrl] = useState(false)
  const [pendingUrl, setPendingUrl] = useState(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState('')
  const [verification, setVerification] = useState(startAtOptions ? 'success' : 'idle')
  const [scenario, setScenario] = useState('success')
  const [expiresAt, setExpiresAt] = useState(startAtOptions ? Date.now() + 60 * 60 * 1000 : null)
  const [now, setNow] = useState(Date.now())
  const [includeXss, setIncludeXss] = useState(false)
  const [useLogin, setUseLogin] = useState(false)
  const [loginUrl, setLoginUrl] = useState('')
  const [loginIdentifier, setLoginIdentifier] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [consent, setConsent] = useState(false)
  const [submitted, setSubmitted] = useState(false)
  const diagnosisLabel = includeXss ? '基本チェック＋XSS確認（反射型）' : '基本チェック'
  const busy = ['checking', 'waiting', 'rechecking'].includes(verification)
  const expired = expiresAt !== null && now >= expiresAt
  const heading = useRef(null)
  const changeDialog = useRef(null)
  useEffect(() => { heading.current?.focus() }, [step])
  useEffect(() => {
    if (pendingUrl && !changeDialog.current.open) changeDialog.current.showModal()
    else if (!pendingUrl && changeDialog.current.open) changeDialog.current.close()
  }, [pendingUrl])
  useEffect(() => {
    if (step !== 2) return
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [step])
  useEffect(() => {
    if (expired && verification !== 'success') setVerification('expired')
  }, [expired, verification])
  useEffect(() => {
    if (step !== 2 || !busy || expired) return
    const timer = setTimeout(() => {
      if (verification === 'waiting') {
        setVerification('rechecking')
      } else if (scenario === 'unreachable') {
        setVerification('unreachable')
      } else if (scenario === 'success') {
        setVerification('success')
      } else if (verification === 'checking') {
        setVerification('waiting')
      } else {
        setVerification('missing')
      }
    }, verification === 'waiting' ? 20_000 : 1000)
    return () => clearTimeout(timer)
  }, [step, verification, scenario, busy, expired])

  function resetVerification() {
    setVerification('idle')
    setExpiresAt(null)
    setCopied('')
    setConsent(false)
    setSubmitted(false)
    setUseLogin(false)
    setLoginUrl('')
    setLoginIdentifier('')
    setLoginPassword('')
  }

  function issuePreviewTag() {
    const issuedAt = Date.now()
    setNow(issuedAt)
    setExpiresAt(issuedAt + 60 * 60 * 1000)
    setVerification('idle')
    setCopied('')
  }

  function returnWithoutUrlChange() {
    setDraftUrl(url)
    setEditingUrl(false)
    setPendingUrl(null)
    setError('')
    setStep(4)
  }

  function confirmUrlChange() {
    setUrl(pendingUrl)
    setDraftUrl(pendingUrl)
    resetVerification()
    issuePreviewTag()
    setPendingUrl(null)
    setEditingUrl(false)
    setError('')
    setStep(2)
  }

  function next(event) {
    event.preventDefault()
    if ((step === 0 && !ready) || (step === 2 && verification !== 'success')) return
    if (step === 3 && useLogin) {
      try {
        const parsed = new URL(loginUrl)
        if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.origin !== new URL(url).origin || !loginIdentifier.trim() || !loginPassword) throw new Error()
      } catch {
        setError('診断対象サイトと同じドメイン・通信方式のログインURL、テスト用ID、テスト用パスワードを入力してください。')
        return
      }
    }
    if (step === 4) {
      if (consent && verification === 'success') {
        setSubmitted(true)
        setLoginPassword('')
      }
      return
    }
    if (step === 1) {
      try {
        const parsed = new URL(draftUrl.trim())
        if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error()
        if (editingUrl) {
          if (parsed.href === url) returnWithoutUrlChange()
          else { setError(''); setPendingUrl(parsed.href) }
          return
        }
        if (parsed.href !== url) resetVerification()
        if (parsed.href !== url || expiresAt === null) issuePreviewTag()
        setUrl(parsed.href)
        setDraftUrl(parsed.href)
      } catch {
        setError('http:// または https:// から始まるURLを入力してください。ID・パスワードを含むURLは使えません。')
        return
      }
    }
    setError('')
    setStep(step + 1)
  }

  async function copyTag() {
    try {
      await navigator.clipboard.writeText(previewTag)
      setCopied('サンプルタグをコピーしました。実際のサイトには設置しないでください。')
    } catch {
      setCopied('コピーできませんでした。タグの文字列を選択してコピーしてください。')
    }
  }

  return <AccountShell home="/preview/top" menu={<span className="account-login-status">プレビュー中</span>}>
    <div className="diagnostic-wizard">
      <p className="wizard-preview-label">{startAtOptions ? '開発用・表示確認のみ：タグ確認済みの状態を仮に再現し、診断内容の選択から開始しています。実際の管理権限確認・通信・診断は行いません。' : '画面確認用プレビュー：ログイン・通信・診断は行いません。'}</p>
      {submitted ? <DiagnosticProgressPreview url={url} diagnosisLabel={diagnosisLabel} useLogin={useLogin} onBack={() => { setSubmitted(false); setConsent(false); setStep(3) }} /> : <>
      <div className="wizard-intro"><h1>診断の準備</h1></div>
      <ol className="wizard-progress" aria-label="準備の手順">{steps.map((label, index) => <li key={label} aria-current={step === index ? 'step' : undefined} className={step === index ? 'is-current' : step > index ? 'is-done' : ''}><span>{index + 1}</span>{label}</li>)}</ol>
      <form className="wizard-card" onSubmit={next}>
        <p className="wizard-eyebrow">STEP {step + 1} / {steps.length}</p>
        <h2 ref={heading} tabIndex={-1}>{steps[step]}</h2>
        {step === 0 && <>
          <div className="wizard-with-art"><div>
            <p className="wizard-lead">本番のサイトを複製し、診断用のテストサイトをご用意ください。</p>
            <div className="wizard-notice"><strong>本番のサイト・データは診断に使わないでください。</strong><p>診断では、フォームへの入力・送信などを行う場合があります。本番サイトで実行すると、データの変更やサービスの動作に影響が出る可能性があります。</p></div>
            <p className="wizard-environment-description">本番とは別の場所にテストサイトを公開し、インターネットからアクセスできるテスト用URLをご用意ください。データベースも本番とは分けてください。</p>
          </div><span className="landing-artwork landing-artwork--test wizard-art" aria-hidden="true"><img src={testArtwork} alt="" /></span></div>
          <section className="wizard-instructions" aria-labelledby="wizard-precautions"><h3 id="wizard-precautions">準備するときの注意事項</h3>
            <ul><li>実際の個人情報は使わず、テスト用のデータを使ってください。</li><li>決済やメール送信も、本番の処理が動かない設定にしてください。</li><li>診断対象のサイトにBOT対策やアクセス制限があると、診断できない、または一部の項目を確認できない場合があります。本番の防御設定は変更しないでください。</li></ul>
          </section>
          <label className="wizard-ready"><input type="checkbox" checked={ready} onChange={event => setReady(event.target.checked)} />本番と分けた診断用のサイトを用意しました</label>
          <div className="wizard-ready-action"><button type="submit" className="wizard-primary" disabled={!ready}>URL入力へ</button></div>
        </>}
        {step === 1 && <>
          <p className="wizard-lead">用意したテスト用サイトのURLを入力してください。</p>
          <label className="wizard-url-label" htmlFor="wizard-url">テスト用URL</label>
          <input id="wizard-url" className="wizard-url" type="text" inputMode="url" autoComplete="off" placeholder="https://test.example.com/" value={draftUrl} aria-invalid={!!error} aria-describedby={error ? 'wizard-url-error' : 'wizard-url-help'} onChange={event => { setDraftUrl(event.target.value); setError('') }} />
          <p id="wizard-url-help" className="wizard-help">このプレビューでは入力形式のみ確認します。サイトにはアクセスしません。</p>
          {error && <p id="wizard-url-error" className="wizard-error" role="alert">{error}</p>}
          <button className="wizard-text-button" type="button" onClick={() => { setDraftUrl('https://test.example.com/'); setError('') }}>サンプルURLを入力する</button>
          <section className="wizard-instructions"><h3>どのURLを入力する？</h3><p>インターネットからアクセスできるテスト用サイトの入口ページを入力してください。本番公開用のURLや、localhostなどのローカル環境のURLは使用しないでください。</p></section>
          <details className="wizard-message-preview"><summary>URLの事前確認で表示する案内（表示見本）</summary>
            <p className="wizard-help">文面確認用です。このプレビューではサイトへのアクセスや判定は行いません。</p>
            <h3>ページが見つからない場合（404）</h3><p>入力したURLのページが見つかりませんでした。URLに誤りがないか、テストサイトが公開されているかをご確認ください。</p>
            <h3>アクセスが拒否された場合（403）</h3><p>診断サーバーからのアクセスが、診断対象のサイトで拒否されました。サイト側のアクセス制限やBOT対策などの設定をご確認ください。</p>
            <h3>原因を特定できない場合</h3><p>診断用サイトにアクセスできませんでした。URLが変わっていないか、サイトが公開されているか、アクセス制限がないかをご確認ください。</p>
            <p className="wizard-help">入口ページにアクセスできても、診断中にアクセスが制限される場合があります。</p>
          </details>
          <div className="wizard-ready-action"><button type="submit" className="wizard-primary">{editingUrl ? '入力したURLで続ける' : 'タグ設置へ'}</button></div>
          {editingUrl && <p className="wizard-help">別のURLで確定すると、確認タグの設置と管理権限の確認をやり直します。ログイン設定も入力し直す必要があります。</p>}
        </>}
        {step === 2 && <>
          <div className="wizard-with-art"><div><p className="wizard-lead">テスト用サイトのHTMLに確認タグを追加します。</p><p>診断対象のサイトを編集・管理できることを確認します。</p></div><span className="landing-artwork landing-artwork--tag wizard-art" aria-hidden="true"><img src={tagArtwork} alt="" /></span></div>
          <div className="wizard-target"><span>確認するテスト用URL</span><strong>{url}</strong></div>
          <p className="wizard-help">以下は表示用のサンプルです。実際のサイトには設置しないでください。</p>
          <div className="wizard-code"><code>{previewTag}</code><button type="button" className="wizard-secondary" onClick={copyTag} disabled={expired}>タグをコピー</button></div>
          <p className="wizard-help">有効期限：{expiresAt && new Date(expiresAt).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit', hour12: false })}まで（発行から60分・プレビュー上の期限）<br />タグの設置確認を完了するまでの期限です。診断を60分以内に終える必要はありません。</p>
          <p className="wizard-help" role="status">{copied}</p>
          <section className="wizard-instructions"><h3>タグの設置手順</h3><ol><li>入力したURLで表示されるトップページのHTMLを開きます（index.htmlなど）。</li><li><code>&lt;head&gt;</code> と <code>&lt;/head&gt;</code> の間に確認タグを追加します。</li><li>変更したページをテスト環境に反映してから、下のボタンでタグの設置を確認します。</li></ol></section>
          <label className="wizard-scenario">表示確認用の結果（実際の通信は行いません）<select value={scenario} disabled={busy} onChange={event => { setScenario(event.target.value); setVerification(expired ? 'expired' : 'idle') }}><option value="success">タグが見つかる</option><option value="missing">タグが見つからない（自動で再確認）</option><option value="unreachable">ページを取得できない</option></select></label>
          <button type="button" className="wizard-primary" onClick={() => setVerification('checking')} disabled={busy || expired || verification === 'success'} aria-busy={busy}>{busy ? <>タグの設置を確認しています<span className="wizard-loading-dots" aria-hidden="true"><span>.</span><span>.</span><span>.</span></span></> : verification === 'success' ? '確認済み（プレビュー）' : 'タグの設置を確認する'}</button>
          <div role="status" aria-live="polite">
            {verification === 'checking' && <p className="wizard-help">タグを確認しています（表示シミュレーション）。</p>}
            {verification === 'waiting' && <p className="wizard-help">反映待ちの可能性があるため、少し時間をおいて自動で再確認します。</p>}
            {verification === 'rechecking' && <p className="wizard-help">もう一度タグを確認しています。</p>}
            {verification === 'missing' && <div className="wizard-notice"><strong>確認タグが見つかりませんでした。</strong><p>公開環境によっては、タグの反映に数分かかる場合があります。設置場所と変更の公開状況を確認し、少し時間をおいてから再度お試しください。</p></div>}
            {verification === 'unreachable' && <div className="wizard-notice"><strong>診断用サイトにアクセスできませんでした。</strong><p>URLが変わっていないか、サイトが公開されているか、アクセス制限がないかをご確認ください。</p><p>URLを変更した場合は、URL入力に戻って新しいURLを入力し、表示された確認タグを対象ページに設置してください。</p><div className="wizard-ready-action"><button type="button" className="wizard-secondary" onClick={() => { setError(''); setVerification('idle'); setStep(1) }}>URL入力に戻る</button></div></div>}
            {verification === 'expired' && <div className="wizard-notice"><strong>確認タグの有効期限が切れました。</strong><p>新しいタグを発行し、サイトに設置したタグを差し替えてください。</p><button type="button" className="wizard-secondary" onClick={issuePreviewTag}>新しいタグを発行する（プレビュー）</button></div>}
            {verification === 'success' && <div className="wizard-success"><strong>管理権限を確認できた場合の表示です。</strong><p>次は診断内容を選び、実行前の注意事項を確認します。</p><p className="wizard-help">実際の管理権限確認・診断は行っていません。</p></div>}
          </div>
          {verification === 'success' && <div className="wizard-ready-action"><button type="submit" className="wizard-primary">診断内容の選択へ</button></div>}
        </>}
        {step === 3 && <>
          <p className="wizard-lead">基本チェックに、必要な確認項目を追加できます。</p>
          <div className="wizard-target"><span>診断するテスト用URL</span><strong>{url}</strong></div>
          <fieldset className="wizard-levels"><legend>診断内容</legend>{diagnosticOptions.map(option => <label key={option.id} className={`wizard-level${option.id === 'basic' || (option.id === 'xss' && includeXss) ? ' is-selected' : ''}${!option.available ? ' is-unavailable' : ''}`}>
            <div className="wizard-level-heading"><input type="checkbox" name="diagnostic-options" value={option.id} checked={option.id === 'basic' || (option.id === 'xss' && includeXss)} disabled={option.id === 'basic' || !option.available} onChange={event => { setIncludeXss(event.target.checked); setConsent(false); setSubmitted(false) }} /><strong>{option.label}</strong><span>{option.id === 'basic' ? '必ず実施' : option.available ? '任意で追加' : '準備中'}</span></div>
            <p>{option.description}</p>{option.checks.length > 0 && <ul>{option.checks.map(check => <li key={check}>{check}</li>)}</ul>}
            {option.coverage && <ul className="wizard-coverage" aria-label="XSSの対応範囲">{option.coverage.map(item => <li key={item.name}><div><strong>{item.name}</strong><span className={`wizard-coverage-status${item.available ? ' is-available' : ''}`}>{item.status}</span></div><p>{item.detail}</p></li>)}</ul>}
            <p className="wizard-help">{option.note}</p>
          </label>)}</fieldset>
          <section className="wizard-instructions" aria-labelledby="wizard-login-title"><h3 id="wizard-login-title">対象サイトにログイン機能がある場合</h3><p>基本チェックでも、ログイン後のページを含める設定ができます。対象にしない場合は、ログインなしで見られるページを診断します。</p><p>ログイン後のページも診断する場合は、対象サイトの診断用アカウントIDとパスワードをご用意ください。NAGeCenアカウントのログイン情報ではありません。</p>
            <label className="wizard-ready"><input type="checkbox" checked={useLogin} onChange={event => { setUseLogin(event.target.checked); setConsent(false); setSubmitted(false); setError(''); if (!event.target.checked) { setLoginUrl(''); setLoginIdentifier(''); setLoginPassword('') } }} />ログイン後のページも診断する</label>
            {useLogin && <div className="wizard-login-fields">
              <div className="wizard-notice"><strong>今回のプレビューには架空の情報だけを入力してください。</strong><p>このプレビューではログイン処理・通信・入力情報の保存は行いません。正式版では、入力した診断用アカウントを使って対象サイトへのログインを試みます。</p><p>本番用・管理者用・NAGeCenのIDやパスワードは入力しないでください。</p></div>
              <label htmlFor="wizard-login-url">診断対象サイトのログイン画面URL</label><input id="wizard-login-url" className="wizard-url" type="url" autoComplete="off" required value={loginUrl} placeholder="https://test.example.com/login" aria-describedby="wizard-login-url-help" onChange={event => { setLoginUrl(event.target.value); setError('') }} />
              <p id="wizard-login-url-help" className="wizard-help">ID・パスワードを入力するログインページのURLです。トップページにログインフォームがある場合は、同じURLを入力してください。</p>
              <label htmlFor="wizard-login-id">テスト用ID／メールアドレスなど</label><input id="wizard-login-id" className="wizard-url" type="text" autoComplete="off" required maxLength={320} value={loginIdentifier} onChange={event => { setLoginIdentifier(event.target.value); setError('') }} />
              <label htmlFor="wizard-login-password">テスト用パスワード</label><input id="wizard-login-password" className="wizard-url" type="password" autoComplete="new-password" required maxLength={1024} value={loginPassword} onChange={event => { setLoginPassword(event.target.value); setError('') }} />
              <p className="wizard-help">ID・パスワードでログインする画面を想定しています。Googleなどの外部ログイン、二段階認証、CAPTCHAがある場合は対応できないことがあります。</p>
            </div>}
          </section>
          {error && <p className="wizard-error" role="alert">{error}</p>}
          <section className="wizard-instructions"><h3>確認できる範囲について</h3><p>巡回できたページと、選んだ診断内容が対象です。ログイン設定を使っても、ログインや巡回ができない部分は確認できません。</p></section>
          <section className="wizard-notice" aria-labelledby="wizard-safety-notice"><h3 id="wizard-safety-notice">診断結果は、安全を保証するものではありません</h3><p>この簡易診断では、選択した項目を検査します。ただし、あらゆる攻撃方法を試したり、すべての問題を確認したりするものではありません。問題が見つからなくても、安全を保証するものではありません。</p></section>
          <p className="wizard-help">暫定案：月5回まで無料。追加項目を含めて診断1回として扱います。回数制限・課金はまだ実装していません。</p>
          <div className="wizard-ready-action"><button type="submit" className="wizard-primary">実行前の確認へ</button></div>
        </>}
        {step === 4 && <>
          <p className="wizard-lead">診断するサイトと、選んだ内容をご確認ください。</p>
          <dl className="wizard-review"><div><dt>テスト用URL</dt><dd>{url}<button type="button" className="wizard-text-button" onClick={() => { setDraftUrl(url); setEditingUrl(true); setConsent(false); setSubmitted(false); setStep(1) }}>URLを変更する</button></dd></div><div><dt>診断内容</dt><dd>{diagnosisLabel}<button type="button" className="wizard-text-button" onClick={() => { setConsent(false); setSubmitted(false); setStep(3) }}>診断内容を変更する</button></dd></div><div><dt>ログイン設定</dt><dd>{useLogin ? 'ログイン後のページも含める（テスト用アカウント）' : 'ログインなしで見られるページのみ'}{useLogin && <p className="wizard-help">ログイン画面：{loginUrl}</p>}<button type="button" className="wizard-text-button" onClick={() => { setConsent(false); setSubmitted(false); setStep(3) }}>ログイン設定を変更する</button></dd></div></dl>
          <div className="wizard-notice"><p className="wizard-repeat-note">繰り返しのご案内となります。</p><strong>本番用のサイトではなく、診断専用のテストサイトで実行してください。</strong><p>巡回やテスト入力によって、データの変更・メール送信などの処理が動く場合があります。</p><ul className="wizard-safety-list"><li><strong>データベースは本番と分けてください。</strong></li><li><strong>決済・メール送信は、テスト用の設定に切り替えるか、無効にしてください。</strong> 実際の決済や、利用者へのメール送信が発生しない状態でご利用ください。</li></ul></div>
          <section className="wizard-instructions"><h3>診断結果の扱い</h3><p>結果は対策を見直すための参考情報です。サイトの安全保証や、NAGeCenによる公開承認ではありません。</p></section>
          <label className="wizard-ready"><input type="checkbox" checked={consent} disabled={submitted} onChange={event => setConsent(event.target.checked)} />自分が管理するテストサイトであり、上記の注意事項を確認しました</label>
          <div className="wizard-ready-action"><button type="submit" className="wizard-primary" disabled={!consent || submitted}>診断開始の操作を試す（プレビュー）</button></div>
        </>}
        <div className="wizard-actions">{step === 1 && editingUrl ? <button type="button" className="wizard-secondary" onClick={returnWithoutUrlChange}>変更せず実行前の確認へ戻る</button> : step > 0 ? <button type="button" className="wizard-secondary" onClick={() => { setError(''); if (busy) setVerification('idle'); setStep(step - 1) }}>戻る</button> : <a href="/preview/top">トップへ戻る</a>}
        </div>
      </form>
      </>}
      <dialog ref={changeDialog} className="wizard-change-dialog" aria-labelledby="wizard-change-title" aria-describedby="wizard-change-description" onCancel={event => { event.preventDefault(); setPendingUrl(null) }}>
        <h2 id="wizard-change-title">URLを変更しますか？</h2>
        <p id="wizard-change-description">URLを変更すると、新しい確認タグの設置と管理権限の確認が必要です。診断対象サイトのログイン設定もリセットされます。</p>
        <div className="wizard-target"><span>変更後のURL</span><strong>{pendingUrl}</strong></div>
        <div className="wizard-dialog-actions"><button type="button" className="wizard-secondary" autoFocus onClick={() => setPendingUrl(null)}>キャンセル</button><button type="button" className="wizard-primary" onClick={confirmUrlChange}>変更してタグ設置へ</button></div>
      </dialog>
      <p className="wizard-footer-note">診断結果は参考情報です。安全を保証するものではありません。</p>
    </div>
  </AccountShell>
}
