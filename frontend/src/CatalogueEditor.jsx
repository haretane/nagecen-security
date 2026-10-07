import { useState } from 'react'

export default function CatalogueEditor({ item, onSaved, onDirty }) {
  const [form, setForm] = useState(item.edit ?? {
    name: item.name, revision: 0, literal_translation: '', title: item.title ?? '',
    description: item.description ?? '', solution: item.solution ?? '', prompt: item.prompt,
    status: 'not_started',
  })
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [dirty, setDirty] = useState(false)
  function change(key, value) {
    setForm(previous => ({ ...previous, [key]: value }))
    setDirty(true); onDirty(true); setMessage('')
  }
  async function save(event) {
    event.preventDefault(); setBusy(true); setMessage('保存中…')
    try {
      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'}/api/development/finding-catalogue`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : '保存できませんでした。入力内容とバックエンドを確認してください。')
      setForm(data.edit); onSaved(data.edit); setDirty(false); onDirty(false)
      setMessage('開発用ファイルへ保存しました。診断画面にはまだ反映されません。')
    } catch (error) { setMessage(error.message) }
    finally { setBusy(false) }
  }
  return <form className="catalogue-editor" onSubmit={save}>
    <h3>説明・翻訳を編集</h3>
    <p className="demo-small">下書き専用です。「確認済み」にしても、実際の診断表示へは自動反映しません。秘密値や個人情報は記入しないでください。</p>
    <fieldset disabled={busy}>
      <label>確認状態<select value={form.status} onChange={e => change('status', e.target.value)}><option value="not_started">未着手</option><option value="draft">下書き</option><option value="reviewed">確認済み</option></select></label>
      {[
        ['literal_translation', '直訳', 12000], ['title', '分かりやすい名称', 500],
        ['description', '分かりやすい説明', 12000], ['solution', '改善案・次に確認すること', 12000],
        ['prompt', 'AI相談用プロンプトの下書き', 20000],
      ].map(([key, label, max]) => <label key={key}>{label}<textarea rows={key === 'prompt' ? 12 : 4} maxLength={max} value={form[key]} onChange={e => change(key, e.target.value)} /></label>)}
      <button type="submit">{busy ? '保存中…' : 'この項目を保存'}</button><span className="demo-small">{dirty ? ' 未保存の変更があります' : ' 未保存の変更はありません'}</span>
    </fieldset>
    <p role="status">{message}</p>
  </form>
}
