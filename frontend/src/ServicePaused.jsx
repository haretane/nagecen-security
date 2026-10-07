import { AccountShell } from './account-login/AccountViews.jsx'
import './landing-page.css'

export default function ServicePaused({ menu, mainUrl }) {
  const dialog = useRef(null)
  useEffect(() => {
    const modal = dialog.current
    modal.showModal()
    return () => modal.close()
  }, [])
  return <AccountShell menu={menu} mainUrl={mainUrl}>
    <section className="account-card"><h1>ログインしています</h1><p>診断機能は一時停止しています。</p>
      <button className="account-menu-button" onClick={() => dialog.current.showModal()}>案内を確認する</button><p><a href="/">トップページへ戻る</a></p>
    </section>
    <ServicePausedDialog dialog={dialog} loggedIn /></AccountShell>
}

export function ServicePausedDialog({ dialog, loggedIn = false }) {
  return <dialog ref={dialog} className="account-card service-paused service-paused-modal" aria-labelledby="service-paused-title">
    <div className="service-paused-modal-header">{loggedIn && <p className="account-login-status">ログイン済み</p>}<button type="button" className="account-menu-button" autoFocus onClick={() => dialog.current.close()}>閉じる</button></div>
    <h1 id="service-paused-title">診断機能は一時停止しています。</h1>
    <div className="landing-notice-panel"><p>NAGeCen 簡易セキュリティ診断は、借りているVPSサーバーに診断ツール「ZAP」を設置して動かしています。当サービスの使用方法が、VPSサービスの規約に沿った利用にあたるか判断が難しいため、利用条件を確認するまで診断機能を停止しています。</p><p>診断の準備から結果の表示までの流れは、プレビューモードでご確認いただけます。プレビューでは、実際の診断は行いません。</p></div>
    <h2>仕組みについて</h2><ol className="service-mechanism">
      <li>VPSのDocker内にオープンソースのセキュリティ診断ソフト「<a href="https://www.zaproxy.org/" target="_blank" rel="noopener noreferrer">ZAP</a>」を設置。</li>
      <li>NAGeCen 簡易セキュリティ診断へ入力いただいた診断対象サイト専用に、所有者確認のためのランダムのメタタグを発行。HTMLに設置していただく。</li>
      <li>所有確認後、VPS内でZAPの自動検査プランを実行。パッシブスキャン、および入力テスト、応答テストを実施。</li>
      <li>ZAPより返ってきた診断結果（英語）を、用意した日本語の対応表に照らし合わせ、NAGeCen上で日本語で説明と改善候補を表示。（未翻訳の項目は現状、英語のまま表示）</li>
    </ol>
    <div className="service-preview-guidance"><p>現在、機能を停止していますが、一連の流れはセキュリティトップページの下にある、プレビューモードから確認できます。</p>
    <a className="landing-start-link" href="/preview/demo">プレビューモード</a><p className="landing-pc-note">※卒業制作 確認用のプレビューモードです。実診断・外部サイトへのアクセスは行いません。</p><p><a href="/">トップページへ戻る</a></p>
    </div></dialog>
}
import { useEffect, useRef } from 'react'
