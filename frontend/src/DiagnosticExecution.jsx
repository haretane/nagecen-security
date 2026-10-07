import { useEffect, useRef, useState } from 'react'
import DiagnosticResults from './DiagnosticResults.jsx'

const terminal = ['completed', 'failed', 'cancelled']

export default function DiagnosticExecution({ client, tag, resumeId, onChangeUrl, preview = false }) {
  const api = useRef(client)
  api.current = client
  const [review, setReview] = useState(false)
  const [xss, setXss] = useState(false)
  const [login, setLogin] = useState(preview)
  const [loginUrl, setLoginUrl] = useState(() => preview ? new URL('login', tag?.target_url || 'https://test.example.com/').href : '')
  const [identifier, setIdentifier] = useState(preview ? 'preview-user@example.com' : '')
  const [password, setPassword] = useState(preview ? 'Preview-Only-Not-A-Real-Password' : '')
  const [consent, setConsent] = useState(false)
  const [job, setJob] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [pollError, setPollError] = useState('')
  const [retry, setRetry] = useState(0)
  const [changeUrl, setChangeUrl] = useState(false)
  const operation = useRef(null)
  const heading = useRef(null)
  const dialog = useRef(null)
  const id = job?.id || resumeId
  const label = xss ? '基本チェック＋XSS確認（反射型）' : '基本チェック'
  useEffect(() => () => operation.current?.abort(), [])
  useEffect(() => { heading.current?.focus() }, [review, job?.status])
  useEffect(() => {
    if (changeUrl) dialog.current?.showModal()
    else dialog.current?.close()
  }, [changeUrl])
  useEffect(() => {
    if (!id || (job && terminal.includes(job.status))) return
    let stopped = false, timer
    const controller = new AbortController()
    async function poll() {
      try {
        const current = await api.current.job(id, controller.signal)
        if (stopped) return
        setJob(current); setPollError('')
        if (!terminal.includes(current.status)) timer = setTimeout(poll, 5000)
      } catch {
        if (!stopped) setPollError('診断状況を取得できませんでした。診断が止まったとは限りません。「状況を再確認する」で確認してください。')
      }
    }
    poll()
    return () => { stopped = true; clearTimeout(timer); controller.abort() }
  }, [id, job?.status, retry])

  async function start() {
    if (!consent || !tag?.verified_target_id || operation.current || job) return
    const controller = new AbortController(); operation.current = controller
    setBusy(true); setError('')
    try {
      const created = await api.current.start({
        verified_target_id: tag.verified_target_id, level_id: xss ? 'xss' : 'basic',
        authorization_confirmed: true, active_scan_confirmed: xss,
        data_change_risk_acknowledged: true, authentication_type: login ? 'form' : 'none',
        service_features: login ? ['login'] : ['unknown'],
        ...(login ? { form_authentication: { login_url: loginUrl, identifier, password } } : {}),
      }, controller.signal)
      if (controller.signal.aborted) return
      setJob(created); setPassword(''); setIdentifier(''); setLoginUrl('')
      // Only an explicit job URL restores a result; initial visits stay clean.
      if (!preview) window.history.replaceState(null, '', '/check?job=' + encodeURIComponent(created.id))
    } catch (failure) {
      if (!controller.signal.aborted) {
        // A lost response can leave a server-side job. Never auto-resubmit.
        setConsent(false)
        setError(failure.status === 429 ? '診断の待機枠が埋まっています。時間をおいて再度お試しください。'
          : failure.code === 'site_not_verified' ? '管理権限の確認情報が無効です。URL入力から確認し直してください。'
          : failure.code === 'login_url_out_of_scope' ? 'ログイン画面URLは、確認したサイトの対象範囲内を指定してください。'
          : '開始の受付を確認できませんでした。通信エラーの場合は依頼済みの可能性もあります。重複実行を避けるため、すぐに押し直さず状況を確認してください。')
      }
    } finally { if (operation.current === controller) operation.current = null; setBusy(false) }
  }
  async function cancel() {
    if (operation.current || job?.status !== 'queued') return
    const controller = new AbortController(); operation.current = controller; setBusy(true)
    try { const updated = await api.current.cancel(job.id, controller.signal); if (!controller.signal.aborted) setJob(updated) }
    catch { if (!controller.signal.aborted) setError('中止できませんでした。すでに診断が始まっている可能性があります。状況を再確認してください。'); setRetry(n => n + 1) }
    finally { if (operation.current === controller) operation.current = null; setBusy(false) }
  }
  if (job?.status === 'completed') return <DiagnosticResults job={job} preview={preview} />
  if (id) return <div className="diagnostic-wizard"><section className="wizard-card">
    <p className="wizard-eyebrow">診断の状況</p><h1>{job?.status === 'queued' ? '診断の順番待ちです' : job?.status === 'running' ? 'テストサイトを診断しています' : job?.status === 'failed' ? '診断を完了できませんでした' : job?.status === 'cancelled' ? '順番待ちを中止しました' : '診断状況を確認しています'}</h1>
    <div role="status">{(!job || ['queued', 'running'].includes(job.status)) && <><span className="wizard-loading-dots" aria-hidden="true"><span>.</span><span>.</span><span>.</span></span><p>ページを巡回し、選んだ診断内容を確認します。診断には数分〜数十分かかる場合があります。</p></>}</div>
    {job && <dl className="wizard-review"><div><dt>対象URL</dt><dd>{job.target_url}</dd></div><div><dt>診断内容</dt><dd>{job.level_id === 'xss' ? '基本チェック＋XSS確認（反射型）' : '基本チェック'}</dd></div><div><dt>巡回したURL</dt><dd>{job.crawled_url_count}</dd></div></dl>}
    {job?.status === 'queued' && <><p>実行できる順番が来るまでお待ちください。Workerが停止している場合は開始されません。</p><button className="wizard-secondary" disabled={busy} onClick={cancel}>順番待ちを中止する</button></>}
    {job?.status === 'running' && <p>実行開始後の中止には対応していません。終了までお待ちください。</p>}
    {job?.status === 'failed' && <p>安全性を判定した結果ではありません。対象サイトの公開状況・アクセス制限をご確認ください。</p>}
    {(pollError || error) && <p className="wizard-error" role="alert">{pollError || error}</p>}
    <button className="wizard-secondary" onClick={() => setRetry(n => n + 1)}>状況を再確認する</button>
    <p><a href={preview ? '/preview/demo' : '/check'}>新しい診断の準備へ</a> ／ <a href="/">トップへ戻る</a></p>
    <p className="wizard-help">{preview ? 'プレビューは待機・実行を模擬しています。再読み込みすると最初に戻ります。履歴は保存しません。' : '再読み込み後もこのURLで状況を確認できます。URLを知っていても別のアカウントでは閲覧できません。'}</p>
  </section></div>
  return <div className="diagnostic-wizard"><section className="wizard-card">
    <p className="wizard-eyebrow">STEP {review ? 5 : 4} / 5</p><h2 ref={heading} tabIndex={-1}>{review ? '実行前の確認' : '診断内容を選択'}</h2>
    <div className="wizard-target"><span>診断するテスト用URL</span><strong>{tag?.target_url}</strong></div>
    {!review ? <form onSubmit={e => { e.preventDefault(); setReview(true); setError('') }}>
      <fieldset className="wizard-levels"><legend>診断内容</legend>
        <label className="wizard-level is-selected"><div className="wizard-level-heading"><input type="checkbox" checked disabled /><strong>基本チェック</strong><span>必ず実施</span></div><p>ページを巡回し、通信・Cookie・セキュリティヘッダーなどの設定を確認します。巡回によってサイトの処理が動く場合があります。</p></label>
        <label className={'wizard-level' + (xss ? ' is-selected' : '')}><div className="wizard-level-heading"><input type="checkbox" aria-label="XSS確認を追加する（反射型）" checked={xss} onChange={e => { setXss(e.target.checked); setConsent(false) }} /><strong>XSS確認を追加する（反射型）</strong></div><p>攻撃を模したテスト入力を送ります。保存型XSS・DOM型XSSは準備中で、今回の診断には含みません。</p></label>
        <label className="wizard-level is-unavailable"><div className="wizard-level-heading"><input type="checkbox" disabled /><strong>SQLインジェクション確認</strong><span>準備中</span></div></label>
      </fieldset>
      <section className="wizard-instructions"><h3>診断対象サイトのログイン設定</h3><p>対象サイトにログイン機能がある場合、基本チェックでもログイン後のページを含める設定ができます。対象にしない場合は、ログイン前のページのみ診断します。</p>
        <label className="wizard-ready"><input type="checkbox" checked={login} onChange={e => { setLogin(e.target.checked); setConsent(false); if (!e.target.checked) { setIdentifier(''); setPassword(''); setLoginUrl('') } }} />ログイン後のページも含める</label>
        {login && <div className="wizard-login-fields"><p>{preview ? 'プレビュー用の架空のID・パスワードを入力してください。実際の認証情報は入力しないでください。入力値は送信・保存しません。' : '診断専用のテストアカウントをご用意ください。実行時にID・パスワードをSecurityサーバーへ送信し、一時保管して対象サイトのログインに使用します。'}</p>
          <label htmlFor="diagnostic-login-url">診断対象サイトのログイン画面URL</label><input id="diagnostic-login-url" className="wizard-url" type="url" required maxLength={2048} autoComplete="off" value={loginUrl} onChange={e => setLoginUrl(e.target.value)} />
          <label htmlFor="diagnostic-login-id">テスト用ID／メールアドレスなど</label><input id="diagnostic-login-id" className="wizard-url" required maxLength={320} autoComplete="off" value={identifier} onChange={e => setIdentifier(e.target.value)} />
          <label htmlFor="diagnostic-login-password">テスト用パスワード</label><input id="diagnostic-login-password" className="wizard-url" type="password" required maxLength={1024} autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} />
          <p>外部ログイン・二段階認証・CAPTCHAなどには対応していません。ログインに失敗した場合、公開ページのみの診断になる場合があります。</p>
        </div>}
      </section><p className="wizard-help">月5回無料の案はまだ未実装です。現在は利用回数・課金の制御はありません。</p>
      <button className="wizard-primary" type="submit">実行前の確認へ</button>
    </form> : <>
      <dl className="wizard-review"><div><dt>診断内容</dt><dd>{label}</dd></div><div><dt>ログイン設定</dt><dd>{login ? 'ログイン後のページも含める' : 'ログインなしで見られるページのみ'}</dd></div></dl>
      <section className="wizard-notice"><p>繰り返しのご案内となります。</p><strong>本番用のサイトではなく、診断専用のテストサイトで実行してください。</strong><p>巡回やテスト入力によって、データの変更・メール送信などの処理が動く場合があります。</p><ul><li>データベースは本番と分けてください。</li><li>決済・メール送信はテスト用の設定に切り替えるか、無効にしてください。実際の決済や利用者へのメール送信が発生しない状態でご利用ください。</li></ul></section>
      <p>結果は対策を見直すための参考情報です。安全の保証や公開承認ではありません。</p>
      <label className="wizard-ready"><input type="checkbox" checked={consent} disabled={busy} onChange={e => setConsent(e.target.checked)} />自分が管理し、診断の実施権限があるテストサイトです。上記の注意事項と{ xss ? '攻撃を模した入力テストによるデータ変更の可能性' : '巡回による影響'}を確認し、実際の診断に同意します</label>
      <div className="wizard-ready-action"><button className="wizard-primary" disabled={!consent || busy} onClick={start}>{busy ? '診断を依頼しています…' : '診断を開始する'}</button></div>
    </>}
    {error && <p className="wizard-error" role="alert">{error}</p>}
    <div className="wizard-actions">{review && <button className="wizard-secondary" disabled={busy} onClick={() => { setReview(false); setConsent(false) }}>診断内容の選択へ戻る</button>}<button className="wizard-secondary" disabled={busy} onClick={() => setChangeUrl(true)}>URLを変更する</button></div>
    <dialog ref={dialog} className="wizard-change-dialog" onCancel={() => setChangeUrl(false)}><h3>URLを変更しますか？</h3><p>変更すると、タグの発行・設置確認をやり直す必要があります。診断設定は破棄します。</p><div className="wizard-dialog-actions"><button className="wizard-secondary" onClick={() => setChangeUrl(false)} autoFocus>変更せず戻る</button><button className="wizard-primary" onClick={onChangeUrl}>変更してURL入力へ</button></div></dialog>
  </section></div>
}
