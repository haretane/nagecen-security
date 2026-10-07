import { useState } from 'react'
import DiagnosticPreparation from './DiagnosticPreparation.jsx'
import { createDemoClient } from './diagnostic-demo-client.mjs'

export default function DiagnosticDemo() {
  const [client] = useState(createDemoClient)
  return <>
    <aside className="demo-banner" role="note">
      <strong>プレビューモード</strong>
      <span>操作体験用です。ログイン・外部通信・実診断・履歴保存は行いません。タグ設置は不要です。</span>
      <a href="/">プレビューを終了</a>
    </aside>
    <DiagnosticPreparation preview client={client} menu={<span className="account-login-status">プレビュー中</span>} />
  </>
}
