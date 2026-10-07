import { useCallback, useEffect, useRef, useState } from 'react'
import DiagnosticPreparation from '../DiagnosticPreparation.jsx'
import { createPreparationClient } from './preparation-client.mjs'
import LandingPage from '../LandingPage.jsx'
import { AccountMenu, AccountShell, LoginPanel, StatusPanel } from './AccountViews.jsx'
import { createAccountClient } from './client.mjs'
import ServicePaused from '../ServicePaused.jsx'
import { diagnosticsPaused } from '../submission-policy.mjs'

export const accountClient = createAccountClient({
  apiBase: import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000',
  authorizationBase: import.meta.env.VITE_NAGECEN_LOGIN_AUTHORIZE_URL ?? 'http://localhost:5173/nagecen/security-login',
})
const MAIN_URL = (import.meta.env.VITE_NAGECEN_LOGIN_AUTHORIZE_URL ?? 'http://localhost:5173/nagecen/security-login').replace(/security-login$/, '')
const ACCOUNT_EVENTS = 'nagecen-security-account-events'

function notifyOtherTabs() {
  if (!globalThis.BroadcastChannel) return
  const channel = new BroadcastChannel(ACCOUNT_EVENTS)
  channel.postMessage('changed') // No tokens, user IDs, URLs, or results.
  channel.close()
}

function CallbackPage({ callbackTask }) {
  const [state, setState] = useState({ phase: 'callback', message: '' })
  useEffect(() => {
    let active = true
    callbackTask().then((result) => {
      if (!active) return
      if (result.status === 'success') {
        notifyOtherTabs()
        window.location.replace('/check')
      } else {
        setState({ phase: 'cancelled', message: '' })
      }
    }).catch((error) => {
      if (active) setState({ phase: 'error', message: error.message })
    })
    // Do not abort/retry the one-use POST during StrictMode's effect cleanup.
    return () => { active = false }
  }, [callbackTask])
  return <AccountShell mainUrl={MAIN_URL}>
    <StatusPanel state={state.phase} message={state.message}
      onStart={state.phase === 'error' ? () => window.location.assign('/login') : undefined} />
  </AccountShell>
}

function AccountPages() {
  const [session, setSession] = useState(null)
  const [phase, setPhase] = useState('loading')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(null)
  const generation = useRef(0)
  const action = useRef(false)
  const hadSession = useRef(false)
  const accountEvents = useRef(null)

  const expire = useCallback(() => {
    generation.current += 1
    setSession(null)
    setPhase('expired')
    setMessage('')
  }, [])

  const refresh = useCallback(async (signal) => {
    if (action.current) return
    const version = ++generation.current
    try {
      const value = await accountClient.session(signal)
      if (signal?.aborted || version !== generation.current) return
      if (value.authenticated) {
        hadSession.current = true
        setSession(value)
        setPhase('authenticated')
      } else {
        setSession(null)
        setPhase(hadSession.current ? 'expired' : 'login')
      }
      setMessage('')
    } catch (error) {
      if (signal?.aborted || version !== generation.current) return
      setSession(null)
      setPhase('error')
      setMessage(error.message)
    }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    refresh(controller.signal)
    const onVisible = () => {
      if (document.visibilityState === 'visible') refresh(controller.signal)
    }
    const timer = window.setInterval(onVisible, 60000)
    window.addEventListener('focus', onVisible)
    document.addEventListener('visibilitychange', onVisible)
    const channel = globalThis.BroadcastChannel ? new BroadcastChannel(ACCOUNT_EVENTS) : null
    accountEvents.current = channel
    if (channel) channel.onmessage = (event) => {
      if (event.data !== 'changed') return
      // Hide old account data before checking a login/logout in another tab.
      generation.current += 1
      setSession(null)
      setPhase('loading')
      refresh(controller.signal)
    }
    return () => {
      controller.abort()
      window.clearInterval(timer)
      window.removeEventListener('focus', onVisible)
      document.removeEventListener('visibilitychange', onVisible)
      channel?.close()
      if (accountEvents.current === channel) accountEvents.current = null
    }
  }, [refresh])

  useEffect(() => {
    if (!session) return
    const timer = window.setTimeout(expire, Math.max(0, Date.parse(session.expires_at) - Date.now()))
    return () => window.clearTimeout(timer)
  }, [session, expire])

  async function start() {
    if (action.current) return
    action.current = true
    generation.current += 1
    setBusy('start')
    setMessage('')
    try {
      window.location.assign(await accountClient.start())
    } catch (error) {
      setMessage(error.message)
    } finally {
      action.current = false
      setBusy(null)
    }
  }

  async function logout() {
    if (action.current) return
    action.current = true
    generation.current += 1
    setBusy('logout')
    // Unmount the diagnostic form/results immediately; never retain another
    // user's form password or result on account changes or uncertain logout.
    setSession(null)
    try {
      await accountClient.logout()
      hadSession.current = false
      // Use the receiving channel itself so the sender tab does not overwrite
      // its own logout-completed screen with a redundant session refresh.
      accountEvents.current?.postMessage('changed')
      setPhase('loggedOut')
      setMessage('')
    } catch (error) {
      setPhase('error')
      setMessage(`ログアウトを確認できませんでした。${error.message}`)
    } finally {
      action.current = false
      setBusy(null)
    }
  }

  const menu = <AccountMenu authenticated={Boolean(session)} busy={Boolean(busy) || phase === 'loading'}
    diagnosticLabel={diagnosticsPaused ? '利用状況を確認' : '診断する'} onLogin={() => window.location.assign('/login')} onLogout={logout} />
  const path = window.location.pathname
  if (path === '/') {
    return <>
      <LandingPage accountMenu={menu} previewNote={false} mainUrl={MAIN_URL} startAction={session
        ? <a className="landing-start-link" href="/check">{diagnosticsPaused ? 'ログイン済み・利用状況を確認' : '診断を始める'}</a>
        : <button type="button" className="landing-start-link account-start-button" onClick={() => window.location.assign('/login')}
            disabled={phase === 'loading' || Boolean(busy)}>NAGeCenアカウントでログインして始める</button>} />
      {phase === 'loggedOut' && <p className="account-banner account-feedback" role="status">Securityからログアウトしました。NAGeCen本体のログイン状態は変わりません。</p>}
      {phase === 'error' && <div className="account-banner account-feedback" role="alert">
        <p>{message}</p><button type="button" className="account-menu-button" onClick={() => refresh()}>接続を再確認する</button>
      </div>}
    </>
  }
  if (path === '/check' && session && !busy) {
    if (diagnosticsPaused) return <ServicePaused menu={menu} mainUrl={MAIN_URL} />
    return <DiagnosticPreparation key={session.account_id} menu={menu} mainUrl={MAIN_URL}
      client={createPreparationClient({ apiBase: import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000', onSessionExpired: expire })} />
  }
  let content
  if (path === '/integrations/nagecen') {
    content = <StatusPanel state="legacy" />
  } else if (phase === 'loading' || busy === 'logout') {
    content = <StatusPanel state="loading" message={busy === 'logout' ? 'ログアウトを確認しています…' : ''} />
  } else if (phase === 'error') {
    content = <StatusPanel state="error" message={message} onRetry={() => refresh()} onStart={start} />
  } else if (phase === 'loggedOut') {
    content = <StatusPanel state="loggedOut" />
  } else if (session) {
    if (diagnosticsPaused) return <ServicePaused menu={menu} mainUrl={MAIN_URL} />
    content = <section className="account-card"><h1>ログインしています</h1>
      <p className="account-description">診断専用のテストURLを用意して、次へ進んでください。</p>
      <a className="landing-start-link" href="/check">診断を始める</a></section>
  } else {
    content = <LoginPanel reason={phase === 'expired' ? 'expired' : 'login'} busy={Boolean(busy)} message={message} onStart={start} />
  }
  return <AccountShell menu={menu} mainUrl={MAIN_URL}>{content}</AccountShell>
}

export default function AccountApplication({ callbackTask }) {
  return window.location.pathname === '/auth/nagecen/callback'
    ? <CallbackPage callbackTask={callbackTask} /> : <AccountPages />
}
