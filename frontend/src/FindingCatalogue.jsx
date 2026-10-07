import { useEffect, useState } from 'react'
import './result-preview.css'
import './finding-catalogue.css'
import CatalogueEditor from './CatalogueEditor.jsx'

export default function FindingCatalogue() {
  const [items, setItems] = useState([])
  const [inventory, setInventory] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('all')
  const [selected, setSelected] = useState('')
  const [dirty, setDirty] = useState(false)
  const [editorVersion, setEditorVersion] = useState(0)
  useEffect(() => {
    const warn = event => { if (dirty) { event.preventDefault(); event.returnValue = '' } }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [dirty])
  function navigate(action) {
    if (dirty && !window.confirm('未保存の変更を破棄して移動しますか？')) return
    if (dirty) setEditorVersion(previous => previous + 1)
    setDirty(false); action()
  }
  useEffect(() => {
    const controller = new AbortController()
    fetch(`${import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'}/api/development/finding-catalogue`, { signal: controller.signal })
      .then(response => { if (!response.ok) throw new Error('対応表を読み込めませんでした。開発用バックエンドの起動を確認してください。'); return response.json() })
      .then(data => { setItems(data.items); setInventory(data.inventory); setSelected(data.items[0]?.name ?? '') })
      .catch(e => { if (e.name !== 'AbortError') setError(e.message) })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [])
  const filtered = items.filter(item => (filter !== 'missing' || !item.mapped) &&
    [item.name, item.title, item.description].join(' ').toLowerCase().includes(query.toLowerCase()))
  const current = filtered.find(item => item.name === selected) ?? filtered[0]
  return <div className="result-demo">
    <header className="demo-header"><a href="/">NAGeCen 簡易セキュリティ診断</a><span className="demo-label">ローカル開発用・下書き編集</span></header>
    <main className="catalogue-main">
      <h1>診断項目の説明・翻訳一覧</h1>
      <p>現在の診断表示と比較しながら、説明・翻訳の下書きを編集できます。保存先は backend/development/finding_edits.json です。</p>
      <aside className="demo-disclaimer"><strong>ZAPの全診断項目を網羅した一覧ではありません。</strong><p>既存の日本語対応表・分類表と、前回の診断で未対応だった2項目を掲載しています。英語の説明全文・直訳・識別番号は未収録です。「登録済み」は文言の監修済みを意味しません。</p></aside>
      <div className="catalogue-stats"><span>掲載 {items.length}項目</span><span>日本語登録済み {items.filter(i => i.mapped).length}項目</span><span>日本語未登録 {items.filter(i => !i.mapped).length}項目</span></div>
      {inventory && <details className="demo-card" open><summary>このSecurityで実行候補となるZAPルール（{inventory.rules.length}種類）</summary>
        <p>ローカルZAP {inventory.version}・{inventory.inspected_at}時点の抽出結果です。本番VPSの搭載内容との一致は未確認です。</p>
        <p>受動診断61種類、選択している能動診断4種類。これは翻訳済み件数ではありません。1ルールから複数の名前の結果が出る場合があります。スクリプト系などは登録内容や条件次第で結果を出さないことがあります。</p>
        <div className="catalogue-rule-table"><table><thead><tr><th>ルールID</th><th>ZAPルール名</th><th>方式</th><th>診断レベル</th></tr></thead><tbody>{inventory.rules.filter(rule => [rule.id, rule.name].join(' ').toLowerCase().includes(query.toLowerCase())).map(rule => <tr key={`${rule.type}-${rule.id}`}><td>{rule.id}</td><td>{rule.name}</td><td>{rule.type === 'passive' ? '受動' : '能動'}</td><td>{rule.levels.join('・')}</td></tr>)}</tbody></table></div>
      </details>}
      <div className="catalogue-filters"><label>項目を検索<input type="search" value={query} onChange={e => navigate(() => setQuery(e.target.value))} placeholder="英語名・日本語・説明" /></label><label>表示対象<select value={filter} onChange={e => navigate(() => setFilter(e.target.value))}><option value="all">すべて</option><option value="missing">日本語未登録のみ</option></select></label></div>
      {loading && <p role="status">読み込み中…</p>}{error && <p role="alert">{error}</p>}
      <div className="catalogue-layout"><nav aria-label="診断項目一覧">{filtered.map(item => <button type="button" key={item.name} className={current?.name === item.name ? 'selected' : ''} aria-pressed={current?.name === item.name} onClick={() => { if (current?.name !== item.name) navigate(() => setSelected(item.name)) }}><strong>{item.title ?? item.name}</strong><small>{item.name}</small><span>{item.mapped ? '日本語登録済み' : '日本語未登録'} / 編集状態：{{not_started: '未着手', draft: '下書き', reviewed: '確認済み'}[item.edit?.status ?? 'not_started']}</span></button>)}</nav>
        {current ? <article className="demo-card catalogue-detail"><h2>{current.title ?? current.name}</h2><p className="demo-small">現在の基本分類：{current.group}（サービスの機能によって分類が変わる項目もあります）</p>
          <section><h3>ZAPの英語名</h3><p>{current.name}</p><h4>英語の説明・対処案</h4><p className="catalogue-missing">未収録。実際の診断結果から取得する原文は、現在の固定対応表には保存されていません。</p></section>
          <CatalogueEditor key={`${current.name}-${editorVersion}`} item={current} onDirty={setDirty} onSaved={edit => setItems(previous => previous.map(item => item.name === edit.name ? { ...item, edit } : item))} />
          <section><h3>意訳・利用者向けの表示</h3><h4>名称</h4><p>{current.title ?? '未登録：英語名が表示されます。'}</p><h4>説明</h4><p>{current.description ?? '未登録：診断時のZAP原文が表示されます。'}</p><h4>改善案</h4><p>{current.solution ?? '未登録：診断時のZAP対処案が表示されます。'}</p></section>
          <section><h3>AI相談用プロンプト</h3><p className="demo-small">現在の共通テンプレートによる表示例です。実際は重要度・対象URL・検出箇所などを差し込みます。</p><pre>{current.prompt}</pre></section>
        </article> : !loading && !error && <p>該当する項目はありません。</p>}
      </div>
    </main>
  </div>
}
