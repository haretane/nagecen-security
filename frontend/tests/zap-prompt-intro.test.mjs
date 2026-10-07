import test from 'node:test'
import assert from 'node:assert/strict'
import { zapPromptIntro } from '../src/zap-prompt-intro.mjs'

const xss = { rule_id: '40012', title: '入力の表示方法', technical_title: 'Cross Site Scripting (Reflected)' }
const hsts = { rule_id: '10035', title: 'HSTSヘッダー未設定', technical_title: 'Strict-Transport-Security Header Not Set' }

test('real prompt identifies the actual ZAP rule and technical name', () => {
  const prompt = zapPromptIntro([xss])
  assert.ok(prompt.startsWith('ZAPを利用した診断結果（ルールID：40012）'))
  assert.match(prompt, /反射型XSSの疑い/)
  assert.match(prompt, /Cross Site Scripting \(Reflected\)/)
  assert.doesNotMatch(prompt, /00000/)
})
test('non-XSS and combined prompts retain their own rules', () => {
  assert.doesNotMatch(zapPromptIntro([hsts]), /反射型XSS/)
  const prompt = zapPromptIntro([xss, hsts])
  assert.match(prompt, /40012/)
  assert.match(prompt, /10035/)
})
test('preview prompt never presents fictional findings as actual evidence', () => {
  const prompt = zapPromptIntro([xss], { preview: true })
  assert.match(prompt, /架空の結果/)
  assert.match(prompt, /実際の検出証拠ではありません/)
  assert.match(prompt, /40012/)
})
