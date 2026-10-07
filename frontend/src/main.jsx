import { lazy, StrictMode, Suspense } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx'
import ResultPreview from './ResultPreview.jsx'
import FindingCatalogue from './FindingCatalogue.jsx'
import InputPreview from './InputPreview.jsx'
import './styles.css'
import { captureCallback, createCallbackTask } from './account-login/client.mjs'
import { wizardPreviewStart } from './wizard-preview-start.mjs'

const LandingPage = (import.meta.env.DEV || import.meta.env.VITE_SECURITY_SUBMISSION_MODE === 'true') ? lazy(() => import('./LandingPage.jsx')) : null
const DiagnosticWizardPreview = import.meta.env.DEV ? lazy(() => import('./DiagnosticWizardPreview.jsx')) : null
const demoEnabled = import.meta.env.DEV || import.meta.env.VITE_SECURITY_DEMO_ENABLED === 'true'
const DiagnosticDemo = demoEnabled ? lazy(() => import('./DiagnosticDemo.jsx')) : null
const AccountPreview = import.meta.env.DEV ? lazy(() => import('./account-login/AccountPreview.jsx')) : null
const submissionMode = import.meta.env.VITE_SECURITY_SUBMISSION_MODE === 'true'
const HostingPolicies = lazy(() => import('./HostingPolicies.jsx'))
const AccountApplication = (import.meta.env.DEV || submissionMode) ? lazy(() => import('./account-login/AccountApplication.jsx')) : null
const accountEnabled = (import.meta.env.DEV || submissionMode) && import.meta.env.VITE_SECURITY_ACCOUNT_LOGIN_ENABLED === 'true'
// Capture in module scope, not React state/props/storage, and clean the browser
// URL even if disabled. The shared task prevents duplicate code exchange.
const callbackTask = window.location.pathname === '/auth/nagecen/callback'
  ? (() => {
    const payload = captureCallback(window.location, window.history)
    return accountEnabled ? createCallbackTask(payload, {
      complete: async (payload) => (await import('./account-login/AccountApplication.jsx')).accountClient.complete(payload),
      session: async () => (await import('./account-login/AccountApplication.jsx')).accountClient.session(),
    }) : null
  })() : null

function DisabledLogin() {
  return <main className="app-shell"><section className="url-check-card">
    <h1>ログイン連携は準備中です</h1><p>現在の環境では、まだ利用できません。</p><a href="/">Securityトップへ戻る</a>
  </section></main>
}

function DisabledPreview() {
  return <main className="app-shell"><section className="url-check-card">
    <h1>開発用の画面です</h1><p>この入口はローカルの開発環境でのみ利用できます。</p><a href="/">トップへ戻る</a>
  </section></main>
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    {window.location.pathname === '/hosting-policies'
      ? <Suspense fallback={null}><HostingPolicies /></Suspense>
      : window.location.pathname === '/preview/demo'
      ? demoEnabled ? <Suspense fallback={null}><DiagnosticDemo /></Suspense> : <DisabledPreview />
      : window.location.pathname === '/preview/diagnostic-wizard'
      ? import.meta.env.DEV
        ? <Suspense fallback={null}><DiagnosticWizardPreview {...wizardPreviewStart(window.location.search)} /></Suspense>
        : <DisabledPreview />
      : import.meta.env.DEV && window.location.pathname === '/preview/account-login'
      ? <Suspense fallback={null}><AccountPreview /></Suspense>
      : import.meta.env.DEV && window.location.pathname === '/preview/top'
      ? <Suspense fallback={null}><LandingPage /></Suspense>
      : import.meta.env.DEV && window.location.pathname === '/preview/input'
      ? <InputPreview />
      : import.meta.env.DEV && window.location.pathname === '/development/findings'
      ? <FindingCatalogue />
      : window.location.pathname === '/preview/results' ? <ResultPreview />
      : submissionMode ? <Suspense fallback={null}><LandingPage previewNote={false} /></Suspense>
      : accountEnabled ? <Suspense fallback={null}><AccountApplication callbackTask={callbackTask} /></Suspense>
      : ['/login', '/check', '/auth/nagecen/callback'].includes(window.location.pathname)
      ? <DisabledLogin /> : <App />}
  </StrictMode>,
)
