import { useEffect, useRef, useState } from 'react'
import { AccountShell } from './account-login/AccountViews.jsx'
import testArtwork from './assets/landing/step-01-test.png'
import tagArtwork from './assets/landing/step-02-tag.png'
import './diagnostic-wizard-preview.css'
import DiagnosticExecution from './DiagnosticExecution.jsx'

const steps = ['テスト用環境を準備', 'テスト用URLを入力', '確認タグを設置']

// AccountApplication mounts this only in authenticated local development.
// Live account flow; scan submission requires a separately confirmed action.
export default function DiagnosticPreparation({ client, menu, mainUrl, preview = false }) {
  const [step, setStep] = useState(0)
  const [ready, setReady] = useState(false)
  const [draftUrl, setDraftUrl] = useState('')
  const [previewUrlFilled, setPreviewUrlFilled] = useState(false)
  const [tag, setTag] = useState(null)
  const [state, setState] = useState('idle')
  const [error, setError] = useState('')
  const [copied, setCopied] = useState('')
  const [copySucceeded, setCopySucceeded] = useState(false)
  const [now, setNow] = useState(Date.now())
  const [execution, setExecution] = useState(false)
  const resumeId = preview ? null : new URLSearchParams(window.location.search).get('job')
  const resumable = /^[0-9a-f-]{36}$/.test(resumeId ?? '') ? resumeId : null
  const operation = useRef(null)
  const heading = useRef(null)
  const tagHelp = useRef(null)
  const busy = ['issuing', 'checking', 'waiting', 'rechecking'].includes(state)
  const expired = tag && now >= Date.parse(tag.expires_at)
  useEffect(() => () => operation.current?.abort(), [])
  useEffect(() => { heading.current?.focus() }, [step])
  useEffect(() => {
    if (!copySucceeded) return
    const timer = setTimeout(() => setCopySucceeded(false), 2500)
    return () => clearTimeout(timer)
  }, [copySucceeded])
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [])

  function back() {
    operation.current?.abort()
    operation.current = null
    setState('idle')
    setError('')
    setStep(current => current - 1)
  }

  async function issue(event) {
    event.preventDefault()
    if (operation.current) return
    const controller = new AbortController()
    operation.current = controller
    setState('issuing')
    setError('')
    setCopied('')
    setCopySucceeded(false)
    // Clear the former target before validating another URL. A failed request
    // must never leave an old verified target associated with the new input.
    setTag(null)
    try {
      const result = await client.validate(draftUrl.trim(), controller.signal)
      if (controller.signal.aborted) return
      const issued = await client.issue(result.normalized_url, controller.signal)
      if (controller.signal.aborted) return
      setTag(issued)
      setDraftUrl(issued.target_url)
      setNow(Date.now())
      setState('idle')
      setStep(2)
    } catch (failure) {
      if (!controller.signal.aborted) {
        setState('idle')
        setError(failure.status === 429
          ? '確認タグの発行が混み合っているか、発行回数の上限に達しました。時間をおいて再度お試しください。'
          : 'URL確認・タグ発行ができませんでした。URLの入力、インターネットからアクセスできる接続先か、ログイン状態と接続状況をご確認ください。')
      }
    } finally {
      if (operation.current === controller) operation.current = null
    }
  }

  async function confirm() {
    if (operation.current || !tag || expired || state === 'success') return
    const controller = new AbortController()
    operation.current = controller
    setState('checking')
    setError('')
    try {
      let result
      try { result = await client.confirm(tag, controller.signal) }
      catch (failure) {
        if (failure.code !== 'meta_not_found' || controller.signal.aborted) throw failure
        setState('waiting')
        await new Promise((resolve, reject) => {
          const cancel = () => { clearTimeout(timer); reject(new Error('aborted')) }
          const timer = setTimeout(() => { controller.signal.removeEventListener('abort', cancel); resolve() }, 20_000)
          controller.signal.addEventListener('abort', cancel, { once: true })
        })
        if (controller.signal.aborted) return
        setState('rechecking')
        result = await client.confirm(tag, controller.signal)
      }
      if (controller.signal.aborted) return
      if (!result.verified || !result.verified_target_id) throw new Error('invalid_response')
      setTag(current => ({ ...current, verified_target_id: result.verified_target_id }))
      setState('success')
    } catch (failure) {
      if (!controller.signal.aborted) {
        setState(failure.code === 'expired' ? 'expired' : failure.code === 'meta_not_found' ? 'missing' : 'error')
        if (failure.code !== 'meta_not_found' && failure.code !== 'expired') setError(failure.status === 429
          ? '確認回数の上限に達しました。時間をおいて再度お試しください。必要に応じてタグを再発行してください。'
          : 'タグの確認を完了できませんでした。URLが変わっていないか、サイトが公開されているか、アクセス制限がないかをご確認ください。ログイン状態と接続状況もご確認ください。')
      }
    } finally {
      if (operation.current === controller) operation.current = null
    }
  }

  async function copyTag() {
    if (preview) tagHelp.current?.showModal()
    setCopySucceeded(false)
    try { await navigator.clipboard.writeText(tag.meta_tag); setCopied('タグをコピーしました。'); setCopySucceeded(true) }
    catch { setCopied('コピーできませんでした。タグを選択してコピーしてください。') }
  }

  if (execution || resumable) return <AccountShell menu={menu} mainUrl={mainUrl}>
    <DiagnosticExecution client={client} tag={tag} resumeId={resumable} preview={preview} onChangeUrl={() => {
      setExecution(false); setTag(null); setState('idle'); setStep(1)
    }} />
  </AccountShell>

  return <AccountShell menu={menu} mainUrl={mainUrl}>
    <div className="diagnostic-wizard">
      <p className="wizard-preview-label">{preview ? 'プレビューモード：「診断を開始する」を押しても実診断は行わず、サンプル結果を表示します。' : 'ローカル実装検証：実行前の確認画面で「診断を開始する」を押すと、実際の診断を依頼します。'}</p>
      {import.meta.env.DEV && !preview && <p className="wizard-help">
        <a className="wizard-text-button" href={`/preview/diagnostic-wizard?start=options&url=${encodeURIComponent(tag?.target_url || draftUrl || 'https://test.example.com/')}`} target="_blank" rel="noopener noreferrer">画面確認用：タグ設置を省いて診断内容の選択から進む</a><br />
        別タブで開きます。実際の診断は行わず、確認済み情報も変更しません。
      </p>}
      <div className="wizard-intro"><h1>診断の準備</h1></div>
      <ol className="wizard-progress wizard-preparation-progress" aria-label="準備の手順">{steps.map((label, index) => <li key={label} aria-current={step === index ? 'step' : undefined} className={step === index ? 'is-current' : step > index ? 'is-done' : ''}><span>{index + 1}</span>{label}</li>)}</ol>
      <section className="wizard-card">
        <p className="wizard-eyebrow">STEP {step + 1} / 3</p>
        <h2 ref={heading} tabIndex={-1}>{steps[step]}</h2>
        {step === 0 && <>
          <div className="wizard-with-art"><div><p className="wizard-lead">本番のサイトを複製し、診断用のテストサイトをご用意ください。</p>
          <div className="wizard-notice"><strong>本番のサイト・データは診断に使わないでください。</strong><p>診断ではフォームへの入力・送信などを行う場合があります。データの変更やサービスの動作に影響が出る可能性があります。</p></div>
          <p className="wizard-environment-description">本番とは別の場所にテストサイトを公開し、インターネットからアクセスできるテスト用URLをご用意ください。データベースも本番とは分けてください。</p></div><span className="landing-artwork landing-artwork--test wizard-art" aria-hidden="true"><img src={testArtwork} alt="" /></span></div>
          <section className="wizard-instructions"><h3>準備するときの注意事項</h3><ul><li>実際の個人情報は使わず、テスト用のデータを使ってください。</li><li>決済・メール送信はテスト用の設定に切り替えるか、無効にしてください。</li><li>BOT対策やアクセス制限により、確認できない場合があります。本番の防御設定は変更しないでください。</li></ul></section>
          <label className="wizard-ready"><input type="checkbox" checked={ready} onChange={event => setReady(event.target.checked)} />本番と分けた診断用のサイトを用意しました</label>
          <div className="wizard-ready-action"><button type="button" className="wizard-primary" disabled={!ready} onClick={() => setStep(1)}>URL入力へ</button></div>
        </>}
        {step === 1 && <form onSubmit={issue}>
          <p className="wizard-lead">{preview ? 'プレビュー用のURLを入力してください。実際のサイトは用意しなくても進めます。' : '用意したテスト用サイトのURLを入力してください。'}</p>
          <label className="wizard-url-label" htmlFor="preparation-url">{preview ? 'プレビュー用URL（実際にはアクセスしません）' : 'テスト用URL'}</label>
          <input id="preparation-url" className="wizard-url" type="url" required maxLength={2048} autoComplete="off" value={draftUrl} disabled={busy} placeholder="https://test.example.com/" aria-invalid={!!error} aria-describedby="preparation-url-help" onChange={event => { setDraftUrl(event.target.value); setPreviewUrlFilled(false); setError('') }} />
          <p id="preparation-url-help" className="wizard-help">{preview ? '下のボタンでサンプルURLを入力できます。対象サイトへのアクセスや実際のタグ発行は行いません。' : 'URL形式と接続先IPの安全性を確認し、タグを発行します。この段階では404やアクセス制限は判定しません。localhostなどのローカル環境のURLは使用できません。'}</p>
          <p className="wizard-help">{preview ? 'プレビューではタグの設置は不要です。「タグの設置を確認する」で確認成功の動きを体験できます。このタグは実際の診断には使えません。' : '表示されたタグをテスト用サイトに設置してください。タグは発行ごとに変わります。'}</p>
          {preview && <div className="wizard-ready-action"><button type="button" className="wizard-secondary" disabled={busy} onClick={() => { setDraftUrl('https://test.example.com/'); setPreviewUrlFilled(true); setError('') }}>{previewUrlFilled ? '入力済み' : 'プレビュー用のURLを入力'}</button></div>}
          <div className="wizard-ready-action"><button type="submit" className="wizard-primary" disabled={busy} aria-busy={busy}>{busy ? 'URL確認・タグ発行中…' : 'タグ設置へ'}</button></div>
        </form>}
        {step === 2 && tag && <>
          <div className="wizard-with-art"><div><p className="wizard-lead">テスト用サイトのHTMLに確認タグを追加します。</p>
          <p>診断対象のサイトを編集・管理できることを確認します。</p></div><span className="landing-artwork landing-artwork--tag wizard-art" aria-hidden="true"><img src={tagArtwork} alt="" /></span></div>
          <div className="wizard-target"><span>確認するテスト用URL</span><strong>{tag.target_url}</strong></div>
          <section className="wizard-tag-section" aria-labelledby="preparation-tag-title">
          <h3 id="preparation-tag-title">編集・管理権限の確認用タグ</h3>
          <div className="wizard-code"><code>{tag.meta_tag}</code><button type="button" className={`wizard-secondary wizard-tag-copy-button${copySucceeded ? ' is-copied' : ''}`} onClick={copyTag} disabled={expired}>{copySucceeded ? 'コピーしました' : 'タグをコピー'}</button></div>
          <p className="wizard-help">有効期限：{new Date(tag.expires_at).toLocaleString('ja-JP')}まで（現在は発行から30分）<br />タグ設置の確認期限です。診断完了までの制限時間ではありません。</p>
          <p className="wizard-help" role="status">{copied}</p>
          </section>
          <section className="wizard-instructions" aria-labelledby="preparation-tag-purpose"><h3 id="preparation-tag-purpose">なぜタグを埋め込むの？</h3>
            <p>診断では、ページの巡回や、通常とは異なるテスト入力を行う場合があります。許可なく第三者のサイトに実施しないよう、確認タグを使って、対象サイトを編集・管理できることを確認します。</p>
            <p>診断は、ご自身が管理し、診断を実施する権限のあるテストサイトで行ってください。診断完了後は、確認タグを削除して構いません。</p>
          </section>
          <section className="wizard-instructions"><h3>タグの設置手順</h3><ol><li>入力したURLで表示されるトップページのHTMLを開きます（index.htmlなど）。</li><li><code>&lt;head&gt;</code> と <code>&lt;/head&gt;</code> の間に確認タグを追加します。</li><li>変更したページをテスト環境に反映してから、タグの設置を確認します。</li></ol></section>
          <button type="button" className="wizard-primary" onClick={confirm} disabled={busy || expired || state === 'success'} aria-busy={busy}>{busy ? <>タグの設置を確認しています<span className="wizard-loading-dots" aria-hidden="true"><span>.</span><span>.</span><span>.</span></span></> : state === 'success' ? '確認済み' : 'タグの設置を確認する'}</button>
          <div role="status" aria-live="polite">
            {state === 'waiting' && <p className="wizard-help">タグの反映待ちの可能性があるため、少し時間をおいて、タグの設置をもう一度だけ自動で確認します。</p>}
            {state === 'missing' && <div className="wizard-notice"><strong>確認タグが見つかりませんでした。</strong><p>自動での再確認は終了しました。タグの反映に数分かかる場合があります。設置場所と公開状況を確認し、間を空けて「タグの設置を確認する」を押してください。</p></div>}
            {(expired || state === 'expired') && state !== 'success' && <div className="wizard-notice"><strong>確認タグの有効期限が切れました。</strong><p>URL入力に戻り、新しいタグを発行して差し替えてください。</p></div>}
            {state === 'success' && <div className="wizard-success"><strong>テストサイトの管理権限を確認できました。</strong><p>次は診断内容を選び、実行前の注意事項を確認します。診断はまだ実行していません。</p><button type="button" className="wizard-primary" onClick={() => setExecution(true)}>診断内容の選択へ</button></div>}
          </div>
          <p className="wizard-help">URLが変わった場合は、URL入力に戻ってタグを再発行し、新しい対象ページへ設置してください。</p>
          {preview && <dialog ref={tagHelp} className="wizard-change-dialog" aria-labelledby="preview-tag-help-title"><h3 id="preview-tag-help-title">ここで実際は、タグをHTMLのheadに埋め込んでいただきます</h3><button className="wizard-secondary" type="button" autoFocus onClick={() => tagHelp.current.close()}>閉じる</button></dialog>}
        </>}
        {error && <p className="wizard-error" role="alert">{error}</p>}
        <div className="wizard-actions">{step > 0 ? <button type="button" className="wizard-secondary" onClick={back}>戻る</button> : <a href="/">トップへ戻る</a>}</div>
      </section>
    </div>
  </AccountShell>
}
