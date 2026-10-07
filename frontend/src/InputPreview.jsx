import { useState } from 'react'
import './result-preview.css'
import './input-preview.css'

export default function InputPreview() {
  const [mode, setMode] = useState('direct')
  const [url, setUrl] = useState('')
  const [message, setMessage] = useState('')
  function changeMode(value) { setMode(value); setMessage('') }
  function proceed(event) {
    event.preventDefault()
    setMessage('表示例：次はサービスの機能・ログイン方式・診断内容を選ぶ画面へ進みます。URLへのアクセスや診断は行っていません。')
  }
  return <div className="result-demo input-demo">
    <header className="demo-header"><a href="/">NAGeCen <span>簡易セキュリティ診断</span></a><span className="demo-label">入力画面の仮イメージ</span></header>
    <main className="input-demo-main">
      <aside className="input-demo-switch" aria-label="表示パターンの選択"><span>表示を比較：</span><button type="button" aria-pressed={mode === 'direct'} onClick={() => changeMode('direct')}>直接訪問</button><button type="button" aria-pressed={mode === 'handoff'} onClick={() => changeMode('handoff')}>NAGeCenから移動</button><p>サンプル画面です。ログイン・URL確認・診断は実行しません。</p></aside>
      <section className="input-demo-hero"><p className="demo-eyebrow">Webサービスの簡易セキュリティ診断</p><h1>Webサービスの<br />セキュリティを確認する。</h1><p className="input-demo-lead">対象ページを自動で巡回し、セキュリティ上の懸念や設定の改善候補をまとめます。</p></section>
      <ol className="input-demo-steps" aria-label="診断までの流れ"><li aria-current="step"><span>1</span>対象URL</li><li><span>2</span>診断内容</li><li><span>3</span>管理権限の確認</li><li><span>4</span>確認・開始</li></ol>
      <div className="input-demo-grid">
        <section className="demo-card input-demo-form-card" aria-labelledby="input-demo-target-title"><p className="demo-eyebrow">STEP 1</p><h2 id="input-demo-target-title">{mode === 'direct' ? '診断するURLを入力' : '引き継いだURLを確認'}</h2>
          <form onSubmit={proceed}>
            {mode === 'direct' ? <><label htmlFor="preview-target-url">対象ページのURL</label><p className="demo-small" id="preview-url-help">インターネットからアクセスできるURLを入力してください。</p><input id="preview-target-url" aria-describedby="preview-url-help" type="url" placeholder="https://test.example.com" required maxLength={2048} value={url} onChange={event => { setUrl(event.target.value); setMessage('') }} /><p className="demo-small">localhostや内部ネットワークのURLは診断できません。</p></> : <><p className="demo-small">NAGeCenから対象URLを受け取りました。</p><div className="input-demo-inherited-url">https://test.example.com/app/</div><p className="demo-small">結果はこのURLに紐づきます。この画面では別のURLへ変更できません。</p><button type="button" className="input-demo-text-button" onClick={() => setMessage('表示例：NAGeCenへ戻ってURLを変更します。この仮ページでは移動しません。')}>URLを変更するにはNAGeCenへ戻る</button></>}
            <aside className="input-demo-test-note"><strong>テスト環境での診断をおすすめします</strong><p>自動巡回や、診断レベルに応じたテスト入力で、サイトの動作やデータに影響する場合があります。</p><p>本番データを使わない検証用の環境をご用意ください。</p></aside>
            <button type="submit" className="input-demo-primary">{mode === 'direct' ? 'このURLで進む' : 'このURLの診断内容を選ぶ'}<span aria-hidden="true"> →</span></button>
            <p className="input-demo-next-help">次に、サービスの機能と診断範囲を選びます。<br />この操作だけでは診断は始まりません。</p>
            {message && <p className="input-demo-feedback" role="status">{message}</p>}
          </form>
        </section>
        <aside className="input-demo-side" aria-label="利用前の確認事項">
          <section><h2>確認できること</h2><p>自動巡回で到達したページの通信内容や、対応する診断項目を確認します。</p><ul><li>セキュリティ関連のヘッダー設定</li><li>Cookieや公開情報の注意点</li><li>選択したレベルに応じた追加診断</li></ul></section>
          <section><h2>結果の受け止め方</h2><p>結果は診断時点の確認範囲に限られ、安全の保証や公開承認ではありません。</p><p>ソースコード全体や、すべての脆弱性を確認するものではありません。テストURLの結果を本番URLの結果として扱うこともできません。</p></section>
          <section><h2>診断前に管理権限を確認します</h2><p>対象ページへ確認タグを設置できることを確認します。作者本人の身元確認とは異なります。</p></section>
        </aside>
      </div>
      <p className="input-demo-post-note">※この診断は、NAGeCenへのプロダクト投稿に必須ではありません。NAGeCenでは診断の利用や結果にかかわらず投稿できます。</p>
      <div className="input-demo-footer-links"><a href="/">現在のSecurityトップを見る</a><a href="/preview/results">診断結果の仮ページを見る</a></div>
    </main>
  </div>
}
