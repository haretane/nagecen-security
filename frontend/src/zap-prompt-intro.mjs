export function zapPromptIntro(findings, { preview = false } = {}) {
  const title = item => String(item.rule_id ?? item.rule) === '40012' ? '反射型XSSの疑い' : item.title
  const rule = item => item.rule_id ?? item.rule ?? '不明'
  if (preview) return ['ZAPを利用した診断結果の表示例です。以下はプレビュー用の架空の結果であり、実際の検出証拠ではありません。',
    ...findings.map(item => `検出候補（表示例）：${title(item)}\nZAPルールID：${rule(item)}\nZAP検査項目：${item.technical_title || item.english || '不明'}`)].join('\n\n')
  if (findings.length === 1) {
    const item = findings[0]
    return `ZAPを利用した診断結果（ルールID：${rule(item)}）に基づき、${title(item)}が報告されています。\nZAP検査項目：${item.technical_title || item.english || '不明'}\n以下の診断結果と、実際のコード・設定を照合し、問題の有無と必要な対策を確認してください。`
  }
  return ['ZAPを利用した診断結果に基づき、以下の検出候補が報告されています。実際のコード・設定と照合してください。',
    ...findings.map(item => `${title(item)}（ルールID：${rule(item)}）\nZAP検査項目：${item.technical_title || item.english || '不明'}`)].join('\n\n')
}
