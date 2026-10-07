import { useRef, useState } from 'react'
import { AccountShell } from './account-login/AccountViews.jsx'
import { zapPromptIntro } from './zap-prompt-intro.mjs'
import './result-preview.css'

const targetUrl = 'https://test.example.com/app/'
const groups = [
  { id: 'important', title: 'リスク：高', description: '実際のコードや設定を確認し、優先して対応を検討してください。' },
  { id: 'consider', title: 'リスク：中', description: 'サイトの構成と実際の影響を確認し、対応を検討してください。' },
  { id: 'low', title: 'リスク：低', description: 'リスクが低い項目も、対応の必要性を確認してください。' },
  { id: 'reference', title: '参考情報', description: '設定や実装を見直すための補足情報です。' },
]
const items = [
  { id: 'xss', group: 'important', title: '入力内容の表示方法に、確認が必要な箇所があります', english: 'Cross Site Scripting (Reflected)', rule: '40012', technical: '反射型XSS', description: '入力した内容がページに表示される箇所で、意図しない処理が動く可能性を検出した例です。実際のコードを確認して判断する必要があります。', why: '入力内容をそのまま表示すると、ブラウザで意図しないスクリプトが実行される場合があります。', action: '入力内容を表示しているコードと、表示場所に応じたエスケープ処理を確認してください。', location: targetUrl + 'search?q=sample', evidence: 'テスト入力が応答へ反映されたという仮の例です。実際の検出証拠ではありません。', count: 1 },
  { id: 'hsts', group: 'consider', title: 'HTTPS接続を継続して使うための設定を見直してください', english: 'Strict-Transport-Security Header Not Set', rule: '10035', technical: 'HSTS', description: '次回以降もHTTPSを使うようブラウザへ伝える設定が見つからなかった例です。', why: 'この設定は、ブラウザがHTTP接続へ戻ってしまうことを抑えるためのものです。', action: 'HTTPSが安定して使えることを確認し、サブドメインへの影響も含めて導入を検討してください。', location: targetUrl, evidence: '応答にHSTSヘッダーがないという仮の例です。', count: 4 },
  { id: 'csp', group: 'consider', title: '読み込むスクリプトなどを制限する設定を検討してください', english: 'Content Security Policy (CSP) Header Not Set', rule: '10038', technical: 'CSP', description: 'ブラウザが読み込めるスクリプトや画像などの取得元を制限する設定が見つからなかった例です。', why: '適切に設定すると、意図しないスクリプトなどが動くことを抑える対策になります。', action: '利用している外部サービスを整理し、画面や機能が壊れないことをテストしながら設定を検討してください。', location: targetUrl, evidence: '応答にCSPヘッダーがないという仮の例です。', count: 4 },
  { id: 'server', group: 'reference', title: '応答にサーバーの種類を示す情報が含まれています', english: 'Server Leaks Version Information via Server HTTP Response Header Field', rule: '10036', technical: 'Serverヘッダー', description: 'サーバーの種類やバージョンを示す情報が応答に含まれている例です。この情報だけで脆弱性があるとは判断できません。', why: '公開する必要のない情報かどうか、サーバー設定を見直す際の参考になります。', action: '表示情報を減らす必要性と、サーバー自体の更新状況を確認してください。情報を隠すだけでは安全にはなりません。', location: targetUrl, evidence: 'サーバー情報が応答に含まれているという仮の例です。', count: 4 },
]

function makePrompt(selected) {
  return [
    zapPromptIntro(selected, { preview: true }),
    '以下はUI検討用のサンプルです。実際の診断証拠ではなく、分類も仮です。脆弱性が確定した情報として扱わないでください。',
    '対象URL（表示例）：' + targetUrl,
    '診断範囲：基本チェック＋反射型XSS。ログイン後のページは未確認。保存型XSS・DOM型XSS・SQLインジェクションは対象外。',
    ...selected.map(item => [
      '項目：' + item.title,
      '分類（仮）：' + groups.find(group => group.id === item.group).title,
      'ZAP項目：' + item.english + ' / ID ' + item.rule,
      '検出の確信度（表示例）：' + item.confidence,
      '対象箇所（例）：' + item.locations.join('、'),
      '検出情報（仮）：' + item.evidence,
      '確認候補：' + item.action,
    ].join('\n')),
    '1. URLや診断結果だけで断定せず、コードと設定を確認してください。必要な資料がなければ質問してください。',
    '2. 対策の必要性、優先順位、変更による影響を説明してください。',
    '3. まだ修正せず、変更案を提示して私の承認を待ってください。',
    '4. 承認後に必要最小限の修正を行い、テスト環境で動作を確認してください。本番変更や新たな診断は別途確認してください。',
    '秘密鍵・パスワード・個人情報を要求したり、ログへ出力したりしないでください。',
  ].join('\n\n')
}

export function PromptCopy({ id, selected, all = false, compact = false, number, buttonLabel, promptOverride }) {
  const [message, setMessage] = useState('')
  const dialogRef = useRef(null)
  const prompt = promptOverride ?? makePrompt(selected)
  async function copy() {
    try {
      await navigator.clipboard.writeText(prompt)
      setMessage('コピーしました。お使いのAIへ貼り付けて相談できます。')
    } catch {
      dialogRef.current.showModal()
      setMessage('コピーできませんでした。プロンプトの文章を選択してコピーしてください。')
    }
  }
  return <div className={compact ? 'result-prompt-row' : 'result-prompt'}>
    <div className={compact ? 'result-prompt-row-heading' : 'result-prompt-controls'}>
      {compact && <h4><span className="result-number">{number}.</span> {selected[0].title}</h4>}
      <div className="result-prompt-buttons">
        <button className="result-content-toggle" type="button" aria-haspopup="dialog" aria-controls={id + '-content'} onClick={() => dialogRef.current.showModal()}>内容を見る</button>
        <button className={all ? 'result-copy primary' : 'result-copy'} type="button" aria-label={compact ? selected[0].title + 'のプロンプトをコピー' : undefined} onClick={copy}>{buttonLabel || (all ? '全項目のプロンプトをコピー' : 'コピー')}</button>
      </div>
    </div>
    <dialog ref={dialogRef} id={id + '-content'} className="result-prompt-dialog" aria-labelledby={id + '-title'}>
      <div className="result-heading"><h3 id={id + '-title'}>{compact ? selected[0].title : all ? '全項目のAIプロンプト' : 'この区分のAIプロンプト'}</h3><button className="result-copy" type="button" onClick={() => dialogRef.current.close()}>閉じる</button></div>
      <label className="result-sr-only" htmlFor={id}>AI確認・修正プロンプト</label><textarea id={id} readOnly value={prompt} rows={12} />
      <button className="result-copy" type="button" onClick={copy}>プロンプトをコピー</button>
      <p className="result-small" role="status">{message}</p>
      {compact && <a className="result-prompt-link" href={'#finding-' + selected[0].id} onClick={() => dialogRef.current.close()}>この項目の診断結果へ戻る ↑</a>}
    </dialog>
    <p className="result-small result-copy-status" role="status">{message}</p>
  </div>
}

export function ConfidenceHelp({ id }) {
  const [open, setOpen] = useState(false)
  return <span className="result-confidence-help" onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)}>
    <button type="button" aria-label="検出の確信度について" aria-expanded={open} aria-describedby={open ? id : undefined} onFocus={() => setOpen(true)} onBlur={() => setOpen(false)} onClick={() => setOpen(true)} onKeyDown={event => { if (event.key === 'Escape') setOpen(false) }}>?</button>
    {open && <span className="result-help-text" role="tooltip" id={id}>問題だと判定する根拠が、どれくらい強いかを表す指標です。ZAPの判定に基づき「高・中・低」で表示します。確信度が高い場合も、実際のコードや設定の確認が必要です。</span>}
  </span>
}

const itemLabels = {
  xss: { title: '反射型XSSの疑い', confidence: '中' },
  hsts: { title: 'HSTSヘッダー未設定', confidence: '高' },
  csp: { title: 'CSPヘッダー未設定', confidence: '高' },
  server: { title: 'サーバー情報の公開', confidence: '中' },
}
const sampleGuidance = {
  csp: {
    why: 'CSPは、ブラウザが読み込めるスクリプトなどの取得元を制限する設定です。未設定の場合、この仕組みによる制限が働きません。ただし、未設定だけで攻撃が成立するとは限りません。',
    action: 'サイトで必要なスクリプトなどの取得元を確認し、それらを許可するCSP設定を検討します。設定によって必要な機能まで止まる場合があるため、テスト環境で動作を確認してから本番へ反映してください。',
  },
}
const sampleLocations = [targetUrl, targetUrl + 'search?q=sample', targetUrl + 'about', targetUrl + 'contact']
const previewItems = items.map(item => ({
  ...item,
  subtitle: item.title,
  ...itemLabels[item.id],
  ...sampleGuidance[item.id],
  group: item.id === 'hsts' || item.id === 'server' ? 'low' : item.group,
  locations: item.count === 1 ? [item.location] : sampleLocations,
}))
const orderedItems = groups.flatMap(group => previewItems.filter(item => item.group === group.id))

export default function ResultPreview() {
  return <AccountShell home="/preview/top" menu={<span className="account-login-status">プレビュー中</span>}>
    <div className="security-results">
      <aside className="result-preview-note">結果画面のプレビューです。URL・件数・検出内容・分類はすべて表示例です。実際の診断や保存は行いません。</aside>
      <header className="result-intro"><p className="result-eyebrow">診断結果</p><h1>確認した内容・改善の候補</h1><p>診断したURLとチェック内容を確認したあと、改善の候補をご覧ください。</p></header>
      <section className="result-panel" aria-labelledby="result-target">
        <div className="result-heading"><h2 id="result-target">診断したURL・チェック内容</h2><span className="result-status">診断処理：完了（表示例）</span></div>
        <p className="result-url">{targetUrl}</p>
        <dl className="result-metadata">
          <div><dt>診断内容</dt><dd>基本チェック＋反射型XSS</dd></div>
          <div><dt>実施日時（例）</dt><dd>2026年10月5日 14:00</dd></div>
          <div><dt>巡回したURL（例）</dt><dd>4 URL</dd></div>
          <div><dt>対象範囲（例）</dt><dd>同じサイトの /app/ 以下</dd></div>
        </dl>
        <details className="result-scope"><summary>今回の診断内容を見る</summary><ul><li>自動巡回で到達したページの基本設定や通信内容</li><li>テスト入力による反射型XSSの確認</li></ul></details>
      </section>
      <section className="result-notice" aria-labelledby="result-unchecked"><h2 id="result-unchecked">確認できなかった範囲があります</h2><p>対象サイトへのログインを完了できず、ログイン後のページは確認できなかった、という表示例です。</p><p className="result-small">保存型XSS・DOM型XSS・SQLインジェクション、ソースコード全体は今回の診断対象外です。「未確認」「対象外」は「問題なし」を意味しません。</p></section>
      <aside className="result-limit"><strong>結果を、設定やコードを見直す手がかりにしてください。</strong><p>この診断では、選択したチェックで見つかった問題や、見直したい設定をまとめています。対策を確認し、改善を進めるために活用してください。</p><p className="result-small">なお、診断で確認できる攻撃手法や脆弱性には限りがあります。「今回の診断では問題は見当たりませんでした」と表示された場合も、サイト全体の安全を保証するものではありません。</p><p className="result-small">本番へ反映する際は、テスト環境で行った対策が、本番のコードや設定にも反映されていることをご確認ください。</p></aside>
      <section className="result-overview" aria-labelledby="result-overview-title"><h2 className="result-major-title" id="result-overview-title"><span aria-hidden="true">■</span> 改善候補を確認する</h2><p className="result-small">リスク区分はZAPの判定に基づきます。実際の影響や対応の必要性は、対象サイトのコードや設定を確認して判断してください。同じ種類の検出を1項目にまとめています。</p>
        <p className="result-small">以下は全{orderedItems.length}項目の表示例です。確信度・対象箇所・説明文はサンプルです。</p>
        <nav className="result-counts" aria-label="改善候補の分類">{groups.map(group => <a className={'result-count ' + group.id} key={group.id} href={'#result-' + group.id}><span>{group.title}</span><strong>{orderedItems.filter(item => item.group === group.id).length} <small>項目</small></strong></a>)}</nav>
      </section>
      <section className="result-details-block" aria-labelledby="result-details-title">
      <h2 className="result-major-title" id="result-details-title"><span aria-hidden="true">■</span> 各リスクの詳細</h2>
      {groups.map(group => <section className="result-group" id={'result-' + group.id} key={group.id} aria-labelledby={'heading-' + group.id}>
        <div className="result-heading result-risk-heading"><h3 id={'heading-' + group.id}>{group.title}</h3><span className="result-risk-count">{orderedItems.filter(item => item.group === group.id).length}項目</span></div><p className="result-small">{group.description}</p>
        {orderedItems.filter(item => item.group === group.id).map(item => <article className="result-panel result-finding" id={'finding-' + item.id} key={item.id}>
          <span className="result-number">{orderedItems.indexOf(item) + 1} / {orderedItems.length}</span>
          <div className="result-indicators">
            <span className={'result-badge ' + group.id}>{group.title}</span>
            <div className="result-confidence">検出の確信度：{item.confidence} <ConfidenceHelp id={'confidence-' + item.id} /></div>
          </div>
          <h3>{item.title}</h3><p className="result-subtitle">{item.subtitle}</p><p>{item.description}</p>
          <section className="result-locations" aria-label={item.title + 'の対象箇所'}><h4>対象箇所（表示例）：{item.locations.length}件</h4><ul>{item.locations.map(location => <li key={location}><code>{location}</code>{item.id === 'xss' && <span className="result-small">入力パラメータ：q（例）</span>}</li>)}</ul></section>
          <dl className="result-action"><div><dt>想定される影響</dt><dd>{item.why}</dd></div><div><dt>対応の進め方</dt><dd>{item.action}</dd></div></dl>
          <details className="result-technical"><summary>英文・技術情報・検出情報を見る</summary><dl><dt>ZAPの英文項目名</dt><dd>{item.english}</dd><dt>技術名</dt><dd>{item.technical}</dd><dt>ZAPルールID</dt><dd>{item.rule}　<a href={'https://www.zaproxy.org/docs/alerts/' + item.rule + '/'} target="_blank" rel="noopener noreferrer">公式の検査ルールを見る ↗</a></dd><dt>検出情報（仮）</dt><dd>{item.evidence}</dd></dl></details>
          <a className="result-prompt-link" href={'#ai-' + item.id}>この項目のAIプロンプトへ ↓</a>
        </article>)}
        {orderedItems.every(item => item.group !== group.id) && <p className="result-empty">この表示例では、この区分に該当する項目は0項目です。</p>}
      </section>)}
      </section>
      <section className="result-next" aria-labelledby="ai-prompts-heading"><h2 className="result-major-title" id="ai-prompts-heading"><span aria-hidden="true">■</span> 対応を相談するためのAIプロンプト</h2><p>対象コードや設定を見ながら、対策の必要性と変更の影響を確認するための文章を用意しています。修正前に変更案を確認し、承認してから進める内容です。</p><p className="result-small">AIへ自動送信はしません。相談時は、秘密鍵・パスワード・個人情報を含めないでください。</p>
        {groups.map(group => {
          const selected = orderedItems.filter(item => item.group === group.id)
          return <section className="result-prompt-risk" aria-labelledby={'ai-group-' + group.id} key={group.id}>
            <div className="result-heading result-risk-heading"><h3 id={'ai-group-' + group.id}>{group.title}</h3><span className="result-risk-count">{selected.length}項目</span></div>
            {selected.length ? <>
              <div className="result-prompt-list">{selected.map(item => <article id={'ai-' + item.id} className="result-prompt-card" key={item.id}><PromptCopy id={'prompt-' + item.id} selected={[item]} compact number={orderedItems.indexOf(item) + 1} /></article>)}</div>
              {selected.length > 1 && <PromptCopy id={'prompt-group-' + group.id} selected={selected} buttonLabel="この区分をまとめてコピー" />}
            </> : <p className="result-small">この表示例では該当する項目はありません。</p>}
          </section>
        })}
        <div className="result-panel"><h3>全項目をまとめて相談する</h3><PromptCopy id="prompt-all" selected={orderedItems} all /></div>
      </section>
      <footer className="result-footer"><a href="/preview/diagnostic-wizard">診断準備のプレビューへ戻る</a><a href="/preview/top">トップページへ戻る</a></footer>
    </div>
  </AccountShell>
}
