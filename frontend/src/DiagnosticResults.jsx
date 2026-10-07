import { ConfidenceHelp, PromptCopy } from './ResultPreview.jsx'
import { zapPromptIntro } from './zap-prompt-intro.mjs'
import './result-preview.css'

const groups = [
  { risk: 'high', id: 'important', title: 'リスク：高' },
  { risk: 'medium', id: 'consider', title: 'リスク：中' },
  { risk: 'low', id: 'low', title: 'リスク：低' },
  { risk: 'info', id: 'reference', title: '参考情報' },
]
export default function DiagnosticResults({ job, preview = false }) {
  const items = groups.flatMap(group => job.findings.filter(item => item.risk === group.risk).map((item, index) => ({
    ...item, id: group.id + '-' + index, group: group.id,
  })))
  const prompt = selected => [zapPromptIntro(selected, { preview }),
    ...(preview ? ['以下はプレビュー用の架空の診断結果です。実際の検出証拠ではありません。'] : []),
    '対象URL：' + job.target_url, '診断内容：' + (job.level_id === 'xss' ? '基本チェック＋反射型XSS' : '基本チェック'),
    '診断時点の検出候補です。脆弱性の確定情報や安全の保証として扱わないでください。',
    ...selected.map(item => [
      '項目：' + (item.rule_id === '40012' ? '反射型XSSの疑い' : item.title),
      'ZAPルールID：' + item.rule_id, 'ZAP検査項目：' + item.technical_title,
      'リスク：' + ({ high: '高', medium: '中', low: '低', info: '参考情報' }[item.risk] || '不明'),
      '検出の確信度：' + (item.confidence_label || '不明'),
      '対象箇所：\n' + (item.locations || []).map(location => [location.url, location.method, location.parameter].filter(Boolean).join(' / ')).join('\n'),
      item.ai_prompt || [item.description, item.solution].join('\n'),
    ].join('\n')),
    '秘密鍵・パスワード・個人情報を含めず、修正前に変更案と影響を説明して承認を待ってください。',
  ].join('\n\n')
  const title = item => item.rule_id === '40012' ? '反射型XSSの疑い' : item.title
  return <div className="security-results">
    {preview && <section className="wizard-notice"><strong>プレビューのサンプル結果です</strong><p>入力したURLを診断した結果ではありません。検出項目・対象箇所・日時は表示例です。</p><a href="/preview/demo">プレビューを最初からやり直す</a></section>}
    <header className="result-intro"><p className="result-eyebrow">診断結果</p><h1>確認した内容・改善の候補</h1><p>診断したURLとチェック内容を確認したあと、改善の候補をご覧ください。</p></header>
    <section className="result-panel"><div className="result-heading"><h2>診断したURL・チェック内容</h2><span className="result-status">診断処理：完了</span></div><p className="result-url">{job.target_url}</p>
      <dl className="result-metadata"><div><dt>診断内容</dt><dd>{job.level_id === 'xss' ? '基本チェック＋反射型XSS' : '基本チェック'}</dd></div><div><dt>完了日時</dt><dd>{job.finished_at ? new Date(job.finished_at).toLocaleString('ja-JP') : '不明'}</dd></div><div><dt>巡回したURL</dt><dd>{job.crawled_url_count} URL</dd></div><div><dt>ログイン確認</dt><dd>{job.authentication_message}</dd></div></dl>
      <h3>診断の範囲</h3><ul>{(job.checked_items || []).map(item => <li key={item.id}>{item.label}</li>)}</ul>
      {!!job.incomplete_items?.length && <div className="wizard-notice"><strong>確認できなかった範囲があります</strong><ul>{job.incomplete_items.map(item => <li key={item.id}>{item.label}</li>)}</ul></div>}
      {!!job.unchecked_items?.length && <details className="result-scope"><summary>今回対象外の項目</summary><ul>{job.unchecked_items.map(item => <li key={item.id}>{item.label}</li>)}</ul></details>}
      <p>この診断では、選択したチェックで見つかった問題や、見直したい設定をまとめています。対策を確認し、改善を進めるために活用できます。</p><p>あらゆる攻撃手法や脆弱性を網羅するものではありません。今回の診断で問題が見当たらなくても、安全を保証するものではありません。</p>
    </section>
    <section className="result-panel"><h2 className="result-major-title">■ 改善候補を確認する</h2><nav className="result-counts" aria-label="改善候補の分類">{groups.map(group => <a key={group.id} className={'result-count ' + group.id} href={'#result-' + group.id}><span>{group.title}</span><strong>{items.filter(item => item.group === group.id).length} <small>項目</small></strong></a>)}</nav>{!items.length && <p>今回の診断では改善候補は見当たりませんでした。確認できなかった範囲がないかもご確認ください。</p>}</section>
    <section className="result-details-block"><h2 className="result-major-title">■ 各リスクの詳細</h2>{groups.map(group => <section key={group.id} className="result-group" id={'result-' + group.id}><div className="result-heading result-risk-heading"><h3>{group.title}</h3><span className="result-risk-count">{items.filter(item => item.group === group.id).length}項目</span></div>
      {items.filter(item => item.group === group.id).map(item => <article key={item.id} className="result-panel result-finding" id={'finding-' + item.id}>
        <span className="result-number">{items.indexOf(item) + 1} / {items.length}</span><div className="result-indicators"><span className={'result-badge ' + group.id}>{group.title}</span><div className="result-confidence">検出の確信度：{item.confidence_label || '不明'} <ConfidenceHelp id={'confidence-' + item.id} /></div></div>
        <h3>{title(item)}</h3><p>{item.description}</p><section className="result-locations"><h4>対象箇所：{item.locations?.length || 0}件</h4><ul>{(item.locations || []).map((location, i) => <li key={i}><code>{location.url}</code><span className="result-small">{location.method} {location.parameter && '入力パラメータ：' + location.parameter}</span></li>)}</ul></section>
        <dl className="result-action"><div><dt>対応の進め方</dt><dd>{item.solution}</dd></div></dl><details className="result-technical"><summary>英文・技術情報を見る</summary><p>{item.technical_title}</p><p>ZAPルールID：{item.rule_id}</p>{/^\d+(?:-\d+)?$/.test(item.rule_id) && <a href={'https://www.zaproxy.org/docs/alerts/' + item.rule_id + '/'} target="_blank" rel="noopener noreferrer">公式の検査ルールを見る ↗</a>}</details><a className="result-prompt-link" href={'#ai-' + item.id}>この項目のAIプロンプトへ ↓</a>
      </article>)}{!items.some(item => item.group === group.id) && <p className="result-empty">この区分に該当する項目は0項目です。</p>}
    </section>)}</section>
    <section className="result-next"><h2 className="result-major-title">■ 対応を相談するためのAIプロンプト</h2><p>AIへ自動送信はしません。相談前に、URLや入力パラメータに秘密情報・個人情報が含まれていないかご確認ください。</p>
      {groups.map(group => { const selected = items.filter(item => item.group === group.id); return <section className="result-prompt-risk" key={group.id}><div className="result-heading result-risk-heading"><h3>{group.title}</h3><span className="result-risk-count">{selected.length}項目</span></div>
        <div className="result-prompt-list">{selected.map(item => <article className="result-prompt-card" id={'ai-' + item.id} key={item.id}><PromptCopy id={'prompt-' + item.id} selected={[{ ...item, title: title(item) }]} compact number={items.indexOf(item) + 1} promptOverride={prompt([item])} /></article>)}</div>
        {selected.length > 1 && <PromptCopy id={'prompt-group-' + group.id} selected={selected} buttonLabel="この区分をまとめてコピー" promptOverride={prompt(selected)} />}{!selected.length && <p className="result-empty">該当する項目は0項目です。</p>}
      </section>})}
      {items.length > 0 && <PromptCopy id="prompt-all" selected={items} all promptOverride={prompt(items)} />}
    </section><footer className="result-footer"><a href={preview ? '/preview/demo' : '/check'}>新しい診断の準備へ</a><a href="/">トップへ戻る</a></footer>
  </div>
}
