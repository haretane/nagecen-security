import test from 'node:test'
import assert from 'node:assert/strict'
import { wizardPreviewStart } from '../src/wizard-preview-start.mjs'

test('normal wizard still starts with test preparation', () => {
  assert.deepEqual(wizardPreviewStart(''), { startAtOptions: false })
  assert.deepEqual(wizardPreviewStart('?start=anything'), { startAtOptions: false })
})
test('development shortcut accepts a display URL without using a verification token', () => {
  const result = wizardPreviewStart('?start=options&url=https%3A%2F%2Ftest.example.com%2Fapp%2F')
  assert.deepEqual(result, { startAtOptions: true, initialUrl: 'https://test.example.com/app/' })
})
for (const candidate of ['javascript:alert(1)', 'https://name:secret@example.com/', 'invalid', 'x'.repeat(2049)]) {
  test('invalid preview URL falls back to the example', () => {
    assert.equal(wizardPreviewStart(`?start=options&url=${encodeURIComponent(candidate)}`).initialUrl, 'https://test.example.com/')
  })
}
