import { useState } from 'react'
import LandingPage from '../LandingPage.jsx'
import { AccountMenu, AccountShell, LoginPanel, StatusPanel } from './AccountViews.jsx'

const VIEWS = {
  top: 'トップ：ログイン前', login: 'ログインの案内', loggedIn: 'トップ：ログイン後',
  expired: '有効期限切れ', callback: '本体から戻る途中', cancelled: 'ログイン中止',
  loggedOut: 'ログアウト後', error: '接続エラー',
}
const HOME = '/preview/account-login'

// Display-only. This component never mounts App or calls login/diagnostic APIs.
export default function AccountPreview() {
  const initial = new URLSearchParams(window.location.search).get('view')
  const [view, setView] = useState(Object.hasOwn(VIEWS, initial) ? initial : 'top')
  const loggedIn = view === 'loggedIn'
  const menu = <AccountMenu authenticated={loggedIn} preview
    onLogin={() => setView('login')} onLogout={() => setView('loggedOut')} />
  const message = view === 'error' ? 'ログイン連携の準備が整っていないか、接続できません。時間をおいてお試しください。' : ''
  return <>
    <aside className="account-preview-controls" aria-label="画面確認用の操作">
      <label htmlFor="account-preview-view">ログイン画面のプレビュー
        <select id="account-preview-view" value={view} onChange={(event) => setView(event.target.value)}>
          {Object.entries(VIEWS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </label>
      <p>表示だけの確認です。実際のログイン・診断・ログアウトは行いません。上の選択で各画面を確認できます。</p>
    </aside>
    {['top', 'loggedIn'].includes(view)
      ? <LandingPage accountMenu={menu} previewNote={false} startAction={loggedIn
          ? <button type="button" className="landing-start-link account-start-button" disabled>診断を始める（画面確認のみ）</button>
          : <button type="button" className="landing-start-link account-start-button" onClick={() => setView('login')}>NAGeCenアカウントでログインして始める</button>} />
      : <AccountShell menu={menu} home={HOME} mainUrl="https://ucu4.sakura.ne.jp/nagecen/">
          {['login', 'expired'].includes(view)
            ? <LoginPanel reason={view} home={HOME} preview />
            : <StatusPanel state={view} message={message} home={HOME} preview />}
        </AccountShell>}
  </>
}
