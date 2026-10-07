import '../landing-page.css'
import './account-login.css'

export function AccountMenu({ authenticated = false, busy = false, onLogin, onLogout, preview = false, loginLabel = 'ログイン', diagnosticLabel = '診断する' }) {
  return (
    <div className="account-menu" aria-label="アカウントメニュー">
      {authenticated ? <>
        <span className="account-login-status">ログイン中</span>
        <button type="button" className="account-menu-button" onClick={onLogout} disabled={busy}>
          {busy ? '確認中…' : 'ログアウト'}
        </button>
      </> : <button type="button" className="account-menu-button" onClick={onLogin} disabled={busy}>
        {busy ? '確認中…' : loginLabel}
      </button>}
    </div>
  )
}

export function AccountShell({ children, menu, home = '/', mainUrl = 'http://localhost:5173/nagecen/' }) {
  return (
    <div className="security-landing account-page">
      <header className="landing-header">
        <div className="landing-container landing-header-inner">
          <a className="landing-brand" href={home}>
            <span className="landing-brand-name">NAGeCen</span><span>簡易セキュリティ診断</span>
          </a>
          <nav className="account-header-nav" aria-label="メニュー">
            <a className="landing-main-link" href={mainUrl}>NAGeCenへ戻る</a>
            <span className="landing-header-separator" aria-hidden="true">｜</span>
            <a className="landing-main-link" href="/">診断トップに戻る</a>{menu}
          </nav>
        </div>
      </header>
      <main className="account-main landing-container">{children}</main>
    </div>
  )
}

export function LoginPanel({ reason = 'login', busy = false, message = '', onStart, home = '/', preview = false }) {
  const expired = reason === 'expired'
  return (
    <section className="account-card" aria-labelledby="account-title">
      <p className="account-eyebrow">NAGeCen 簡易セキュリティ診断</p>
      <h1 id="account-title">{expired ? 'もう一度ログインしてください' : 'NAGeCenアカウントで始める'}</h1>
      <p className="account-description">
        {expired ? 'ログインの有効期限が切れたか、ログイン状態を確認できなくなりました。'
          : '診断の利用には、NAGeCenアカウントでのログインが必要です。'}
      </p>
      <div className="account-login-explanation">
        <p>NAGeCenの画面でログイン・新規登録を行い、このサイトへ戻ります。</p>
        <p>Security側でパスワードを入力する必要はありません。プロダクトの投稿も不要です。</p>
      </div>
      {expired && <p className="account-help">入力中の情報や表示中の結果は画面から消去します。実行中の診断は、ログインが切れても自動では中止されません。</p>}
      {message && <p className="account-feedback" role="alert">{message}</p>}
      <button type="button" className="account-primary" onClick={onStart} disabled={busy || preview}>
        {busy ? 'ログインの準備をしています…' : 'NAGeCenでログイン・新規登録'}
      </button>
      {preview && <p className="account-help">画面確認用です。本体への移動やログイン処理は行いません。</p>}
      <a className="account-back-link" href={home}>Securityトップへ戻る</a>
      <p className="account-footnote">※この診断は、NAGeCenへのプロダクト投稿に必須ではありません。NAGeCenでは診断の利用や結果にかかわらず投稿できます。</p>
    </section>
  )
}

export function StatusPanel({ state = 'loading', message = '', onStart, onRetry, home = '/', preview = false }) {
  const titles = {
    loading: 'ログイン状態を確認しています', callback: 'Securityへ戻っています',
    cancelled: 'ログインを中止しました', loggedOut: 'ログアウトしました',
    error: 'ログインを確認できませんでした', legacy: '従来の連携は切り替え準備中です',
  }
  return (
    <section className="account-card" aria-labelledby="account-status-title" aria-busy={['loading', 'callback'].includes(state)}>
      <p className="account-eyebrow">NAGeCen 簡易セキュリティ診断</p>
      <h1 id="account-status-title">{titles[state] ?? titles.error}</h1>
      <p className="account-description" role={state === 'error' ? 'alert' : 'status'}>
        {message || (state === 'loggedOut' ? 'Securityからログアウトしました。NAGeCen本体のログイン状態は変わりません。'
          : state === 'cancelled' ? 'Securityへの新しいログインは行っていません。必要なときに、もう一度始められます。'
          : state === 'legacy' ? 'プロダクト連携からの復帰手順は、本体側との確認待ちです。この新認証モードでは従来の連携を自動で引き継ぎません。'
          : 'そのままお待ちください。')}
      </p>
      {onRetry && <button type="button" className="account-primary" onClick={onRetry}>接続を再確認する</button>}
      {onStart && <button type="button" className="account-primary" onClick={onStart} disabled={preview}>ログインを最初からやり直す</button>}
      {state === 'loggedOut' && <p className="account-help">実行中の診断がある場合、ログアウトしても自動では中止されません。</p>}
      {preview && <p className="account-help">画面確認用の表示です。認証・診断・ログアウト処理は行いません。</p>}
      {!['loading', 'callback'].includes(state) && <a className="account-back-link" href={home}>Securityトップへ戻る</a>}
    </section>
  )
}
