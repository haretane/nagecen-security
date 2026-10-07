import { useEffect, useRef, useState } from 'react'

const states = {
  queued: { label: '順番待ち', title: 'ただいま混み合っております。順番待ちとなります。', description: '診断を開始できる順番が来るまでお待ちください。' },
  running: { label: '診断中', title: 'テストサイトを診断しています', description: 'ページを巡回し、選んだ診断内容を確認しています。' },
  completed: { label: '完了', title: '診断が完了しました', description: '結果を確認して、設定やコードの改善にお役立てください。' },
  failed: { label: 'エラー', title: '診断を完了できませんでした', description: '診断中に対象サイトへアクセスできなくなった場合の表示例です。安全性についての判定ではありません。' },
  cancelled: { label: '中止', title: '診断の順番待ちを中止しました', description: '診断は開始していません。必要なときに、設定を見直して再度お試しください。' },
}

export default function DiagnosticProgressPreview({ url, diagnosisLabel, useLogin, onBack }) {
  const [status, setStatus] = useState('queued')
  const heading = useRef(null)
  const current = states[status]
  const pending = ['queued', 'running'].includes(status)
  useEffect(() => { heading.current?.focus() }, [status])

  return <>
    <div className="wizard-intro"><h1>診断の状況</h1></div>
    <label className="wizard-scenario">表示確認用の状態（実際の診断・待機は行いません）<select value={status} onChange={event => setStatus(event.target.value)}>{Object.entries(states).map(([value, state]) => <option key={value} value={value}>{state.label}</option>)}</select></label>
    <section className="wizard-card" aria-labelledby="wizard-progress-title">
      <p className="wizard-eyebrow">{current.label}（プレビュー）</p>
      <h2 id="wizard-progress-title" ref={heading} tabIndex={-1}>{current.title}</h2>
      <div className="wizard-progress-summary"><span className={`wizard-status-mark${pending ? ' is-pending' : ''}`} aria-hidden="true">{pending ? <span className="wizard-loading-dots"><span>.</span><span>.</span><span>.</span></span> : status === 'completed' ? '✓' : '—'}</span><p className="wizard-lead">{current.description}</p></div>
      {status === 'running' && <p className="wizard-duration-note">診断には数分かかる場合があります。対象サイトの応答状況や診断内容によって、所要時間は変わります。順番待ちの時間は別です。</p>}
      <dl className="wizard-review"><div><dt>テスト用URL</dt><dd>{url}</dd></div><div><dt>診断内容</dt><dd>{diagnosisLabel}</dd></div><div><dt>ログイン設定</dt><dd>{useLogin ? 'ログイン後のページも含める' : 'ログインなしで見られるページのみ'}</dd></div></dl>
      {status === 'queued' && <>
        <section className="wizard-instructions"><h3>待機中について</h3><p>待ち時間は、先に実行している診断や対象サイトの応答状況によって変わります。今は画面確認用のため、実際の待ち時間や順番は表示していません。</p></section>
        <button type="button" className="wizard-secondary" onClick={() => setStatus('cancelled')}>順番待ちを中止する（プレビュー）</button>
      </>}
      {status === 'running' && <>
        <section className="wizard-instructions"><h3>診断の実行中です</h3><p>動く「…」は処理中の表示です。画面だけでは正確な進行割合や残り時間は分からないため、パーセントや終了時刻は表示しません。</p><p>現在の実装では、開始後の診断を途中で中止する機能はありません。診断処理が終了するまでお待ちください。</p></section>
      </>}
      {status === 'completed' && <>
        <section className="wizard-notice"><h3>診断が完了しても、安全を保証するものではありません</h3><p>確認できた範囲と、確認できなかった項目を結果で確認してください。</p></section>
        <div className="wizard-ready-action"><a className="wizard-primary wizard-link-button" href="/preview/results">結果画面のサンプルを見る</a></div><p className="wizard-help">リンク先は既存の結果画面の見本です。このURL・診断内容に対する実際の結果ではありません。</p>
      </>}
      {status === 'failed' && <div className="wizard-notice"><strong>診断用サイトにアクセスできませんでした。</strong><p>URLが変わっていないか、サイトが公開されているか、アクセス制限がないかをご確認ください。</p><p>URLを変更する場合は、URL入力から確認タグの設置をやり直してください。</p></div>}
      <div className="wizard-actions"><button type="button" className="wizard-secondary" onClick={onBack}>診断設定のプレビューへ戻る</button><a href="/preview/top">トップへ戻る</a></div>
      <p className="wizard-help">この画面は表示見本です。診断APIの呼び出し、診断の開始・中止、履歴保存、利用回数の消費は行いません。</p>
    </section>
  </>
}
