import { AccountShell } from './account-login/AccountViews.jsx'
import './landing-page.css'

export const hostingServices = [
  { name: 'Render', status: '利用可能', note: '自分のRender上のサービスへのセキュリティ評価を許可。DoSテストやRender基盤への試験は禁止です。', url: 'https://render.com/docs/penetration-testing', source: '侵入テスト方針（英語）' },
  { name: 'Vercel — Hobby', status: '利用不可', note: 'Hobby利用者による侵入テストは禁止されています。', url: 'https://vercel.com/kb/guide/penetration-testing-on-vercel', source: '侵入テスト方針（英語）' },
  { name: 'Vercel — Pro', status: '未確認', note: '公式方針では、通信量の多くない侵入テストを認めています。ただし、通信量の数値基準は記載されておらず、NAGeCen 簡易セキュリティ診断による診断の可否は運営側で確認できていません。', url: 'https://vercel.com/kb/guide/penetration-testing-on-vercel', source: '侵入テスト方針（英語）' },
  { name: 'Vercel — Enterprise', status: '未確認', note: '公式方針では侵入テストを認めていますが、通信量の多い自動検査にはVercelへの事前連絡が必要です。NAGeCen 簡易セキュリティ診断による診断がどの区分に該当するかは、運営側で確認できていません。', url: 'https://vercel.com/kb/guide/penetration-testing-on-vercel', source: '侵入テスト方針（英語）' },
  { name: 'AWS — EC2など指定サービス', status: '利用可能', note: '条件付き。公式方針で許可された自分のサービスが対象。DoS等は禁止です。AWSの全サービスで利用可能という意味ではありません。', url: 'https://aws.amazon.com/jp/security/penetration-testing/', source: '侵入テスト方針（日本語）' },
  { name: 'GitHub Pages', status: '未確認', note: '当サービスの自動診断を許可する条件を確認できていません。不当な負荷や未承認のアクセスは禁止されています。サイトを所有しているだけでは実施可と判断しません。', url: 'https://docs.github.com/ja/site-policy/acceptable-use-policies/github-acceptable-use-policies', source: '利用ポリシー（日本語）' },
  { name: 'エックスサーバー', status: '未確認', note: '当サービスによる自動診断の許可条件は未確認です。', url: 'https://www.xserver.ne.jp/rule/rule.php', source: '利用規約（日本語）' },
  { name: 'さくらのレンタルサーバ', status: '未確認', note: 'NAGeCen 簡易セキュリティ診断による自動診断の許可条件は、運営側で確認できていません。', url: 'https://www.sakura.ad.jp/corporate/agreement/', source: '約款一覧（日本語）' },
  { name: 'さくらのVPS', status: '未確認', note: 'NAGeCen 簡易セキュリティ診断による自動診断の許可条件は、運営側で確認できていません。レンタルサーバやクラウドとは別のサービスです。', url: 'https://www.sakura.ad.jp/corporate/agreement/', source: '約款一覧（日本語）' },
  { name: 'さくらのクラウド', status: '利用可能', note: '公式FAQで、脆弱性診断は事前連絡なしで実施可能と案内されています。他の利用者やサービス継続に影響がある場合は制限されます。', url: 'https://manual.sakura.ad.jp/cloud/support/security/other.html', source: '脆弱性診断の実施条件（日本語）' },
  { name: 'KAGOYA CLOUD VPS', status: '未確認', note: 'NAGeCen 簡易セキュリティ診断による自動診断の許可条件は、運営側で確認できていません。', url: 'https://www.kagoya.jp/terms/', source: '利用規約一覧（日本語）' },
  { name: 'Netlify', status: '未確認', note: '当サービスによる自動診断の許可条件は未確認です。', url: 'https://www.netlify.com/legal/acceptable-use-policy/', source: '利用ポリシー（英語）' },
]

export default function HostingPolicies() {
  return <AccountShell><section className="account-card hosting-policies">
    <h1>ホスティングサービスの診断条件</h1><p>確認日：2026年10月6日</p>
    <p>診断対象サイトを公開しているサービスの公式条件をまとめています。「利用可能」は、記載された条件のもとで試験を認める公式方針があることを示します。NAGeCen 簡易セキュリティ診断の利用を個別に承認されたという意味ではありません。</p>
    <div className="landing-notice-panel"><p>診断機能は現在停止中です。この一覧は実診断を開始するための案内ではありません。</p><p>規約・プラン・診断方法により条件は異なります。未確認は「禁止」とも「許可」とも判断していない状態です。最新の公式条件をご確認ください。</p></div>
    <div className="hosting-service-list">{hostingServices.map(service => <article className="hosting-service" key={service.name}>
      <div className="hosting-service-heading"><h2>{service.name}</h2><span className={'hosting-status ' + (service.status === '利用可能' ? 'allowed' : service.status === '利用不可' ? 'denied' : 'unknown')}>{service.status === '利用不可' && <span aria-hidden="true">× </span>}{service.status}</span></div>
      {service.status === '利用不可' && <p className="hosting-denied-notice">このプランでは診断をご利用いただけません。</p>}
      <p>{service.note}</p><a className="hosting-source-link" href={service.url} target="_blank" rel="noopener noreferrer">{service.source}<span aria-hidden="true"> →</span><span className="hosting-new-tab">（別タブで開きます）</span></a>
    </article>)}</div>
    <p>サイトの所有者の承認と、ホスティング事業者の許可条件は別です。接続先のデータベース・メール・決済など、関連サービスの条件も対象になります。無料枠の有無はこの一覧の可否とは別です。</p><a href="/">トップページへ戻る</a>
  </section></AccountShell>
}
