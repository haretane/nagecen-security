// Preview inputs are display data only. They never authorize a scan.
export function wizardPreviewStart(search) {
  const params = new URLSearchParams(search)
  if (params.get('start') !== 'options') return { startAtOptions: false }
  let initialUrl = 'https://test.example.com/'
  const candidate = params.get('url')
  try {
    if (!candidate || candidate.length > 2048) throw new Error()
    const parsed = new URL(candidate)
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error()
    initialUrl = parsed.href
  } catch { /* Invalid display inputs use the explicitly fictional example. */ }
  return { startAtOptions: true, initialUrl }
}
