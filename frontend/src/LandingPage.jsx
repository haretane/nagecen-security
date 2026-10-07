import { cloneElement, useEffect, useRef } from 'react'
import { ServicePausedDialog } from './ServicePaused.jsx'
import heroImage from './assets/landing/nagecen-security-hero.png'
import testImage from './assets/landing/step-01-test.png'
import tagImage from './assets/landing/step-02-tag.png'
import checkImage from './assets/landing/step-03-check.png'
import './landing-page.css'

const NAGECEN_URL = 'https://ucu4.sakura.ne.jp/nagecen/'
// The existing main-app route. Cross-service login/return is not implemented here.
const NAGECEN_LOGIN_URL = `${NAGECEN_URL}login`

const steps = [
  {
    title: '診断用のサイトを用意する',
    description: '本番公開用のサイトではなく、診断専用のテストURLを用意してください。',
    image: testImage,
    artwork: 'test',
  },
  {
    title: '確認タグを埋め込む',
    description: 'テスト環境のHTMLに指定のタグを追加し、管理権限を確認してください。',
    image: tagImage,
    artwork: 'tag',
  },
  {
    title: '簡易検査を行う',
    description: '診断を実行し、結果と改善候補を確認します。',
    image: checkImage,
    artwork: 'check',
  },
]

function Artwork({ src, name, className = '' }) {
  return (
    <span className={`landing-artwork landing-artwork--${name} ${className}`} aria-hidden="true">
      <img src={src} alt="" width="1254" height="1254" />
    </span>
  )
}

// Development-only visual preview: it does not replace the existing diagnostic flow.
export default function LandingPage({ accountMenu = null, startAction = null, previewNote = true, mainUrl = NAGECEN_URL }) {
  const pauseDialog = useRef(null)
  const submissionEntry = import.meta.env.DEV || import.meta.env.VITE_SECURITY_SUBMISSION_MODE === 'true'
  useEffect(() => {
    const previousTitle = document.title
    document.title = window.location.pathname.startsWith('/preview/')
      ? 'NAGeCen 簡易セキュリティ診断 | トップページプレビュー' : 'NAGeCen 簡易セキュリティ診断'
    return () => { document.title = previousTitle }
  }, [])

  return (
    <div className="security-landing" id="landing-top">
      <header className="landing-header">
        <div className="landing-container landing-header-inner">
          <a className="landing-brand" href="#landing-top" aria-label="NAGeCen 簡易セキュリティ診断 トップ">
            <span className="landing-brand-name">NAGeCen</span>
            <span>簡易セキュリティ診断</span>
          </a>
          <nav className="account-header-nav landing-header-nav" aria-label="メニュー">
            <a className="landing-main-link" href={mainUrl}>NAGeCenへ戻る</a>
            <span className="landing-header-separator" aria-hidden="true">｜</span>
            <a className="landing-main-link" href="/">診断トップに戻る</a>
            {submissionEntry ? <button type="button" className="landing-header-start" onClick={() => pauseDialog.current.showModal()}>ログインして始める</button> : accountMenu ? cloneElement(accountMenu, {
              loginLabel: 'ログインして始める',
            }) : <a className="landing-header-start" href={NAGECEN_LOGIN_URL}>ログインして始める</a>}
          </nav>
        </div>
      </header>

      <main className="landing-main">
        <section className="landing-hero" aria-labelledby="landing-title">
          <div className="landing-container landing-hero-inner">
            <div className="landing-hero-copy">
              <h1 id="landing-title">
                <span className="landing-brand-name">NAGeCen</span>{' '}
                <span>簡易セキュリティ診断</span>
              </h1>
              <p className="landing-overview">
                <span>自分で作成・管理するWebサービスの、</span>
                <span>セキュリティ上の改善点を調べる簡易診断サービスです。</span>
              </p>
              <p className="landing-audience">HTMLに確認タグを追加し、テスト環境を用意できる方へ</p>
            </div>
            <Artwork src={heroImage} name="hero" className="landing-hero-art" />
          </div>
        </section>

        <section className="landing-container landing-steps" aria-labelledby="landing-steps-title">
          <h2 id="landing-steps-title">診断までの3ステップ</h2>
          <ol className="landing-step-list">
            {steps.map((step, index) => (
              <li className="landing-step" key={step.artwork}>
                <span className="landing-step-number" aria-hidden="true">{index + 1}</span>
                <Artwork src={step.image} name={step.artwork} className="landing-step-art" />
                <div className="landing-step-copy">
                  <h3>{step.title}</h3>
                  <p>{step.description}</p>
                </div>
              </li>
            ))}
          </ol>
          <div className="landing-notice">
            <div className="landing-notice-panel">
              <p className="landing-notice-request">
                本番環境（URL）ではなく、テスト環境（テストURL）での診断をお願いします。
              </p>
              <p>診断内容によっては、フォームへの入力・送信などのテストを行います。</p>
              <p>
                本番のサイトをコピーし、データベースも本番とは分けてください。
                診断用のサイトは、インターネットからアクセスできるURLで用意してください。
              </p>
              <p>診断結果は参考情報であり、安全を保証するものではありません。</p>
            </div>
            <div className="landing-notice-panel landing-hosting-notice"><p>ホスティングサイトの規約にて、脆弱性診断等の試験の実行が禁止されている場合があります。<br />各サービスの利用規約をご確認ください。</p><a className="landing-policy-link" href="/hosting-policies" target="_blank" rel="noopener noreferrer">利用規約等へのリンク →</a></div>
          </div>
          <p className="landing-post-note">
            ※この診断は、NAGeCenへのプロダクト投稿に必須ではありません。NAGeCenでは診断の利用や結果にかかわらず投稿できます。
          </p>
          <section className="landing-diagnostic-method" aria-labelledby="landing-method-title">
            <h2 id="landing-method-title">診断の仕組み</h2>
            <p>
              このサービスは、診断エンジンにセキュリティ検査ツール「ZAP」を使用しています。
              AIによる推測ではなく、選択した検査項目と検査ルールに沿って、サイトの応答やテスト入力への反応を自動で確認します。
            </p>
            <p className="landing-method-note">
              ※診断結果をもとに、ご自身でAIへ相談するためのプロンプトも用意していますが、診断そのものにAIは使用しません。
            </p>
          </section>
          <div className="landing-bottom-start">
            {submissionEntry ? <button type="button" className="landing-start-link" onClick={() => pauseDialog.current.showModal()}><span>NAGeCenアカウントで</span><span>ログインして始める</span></button> : startAction ?? <a className="landing-start-link" href={NAGECEN_LOGIN_URL}>
              <span>NAGeCenアカウントで</span><span>ログインして始める</span>
            </a>}
            {(import.meta.env.DEV || import.meta.env.VITE_SECURITY_DEMO_ENABLED === 'true') && <div className="landing-demo-start"><a className="landing-start-link" href="/preview/demo">プレビューモード</a><p className="landing-pc-note">※卒業制作 確認用のプレビューモードです。</p><p className="landing-pc-note">ログイン・タグ設置なしで操作を体験できます。実際の診断は行いません。</p></div>}
            <p className="landing-pc-note">
              診断の準備や詳しい結果の確認は、PCでの利用をおすすめします。
            </p>
          </div>
        </section>
      </main>
      {submissionEntry && <ServicePausedDialog dialog={pauseDialog} />}

      {previewNote && <aside className="landing-preview-note" aria-label="プレビューについて">
        <p className="landing-container">
          デザイン確認用の仮ページです。ログイン先はNAGeCen本体ですが、ログイン後に診断へ戻る連携はまだ接続していません。
          {' '}<a href="/preview/account-login">ログイン画面のプレビューを見る</a>
          {' ／ '}<a href="/preview/diagnostic-wizard">診断準備のプレビューを見る</a>
        </p>
      </aside>}
    </div>
  )
}
