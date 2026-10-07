# Security側アカウント連携：第1〜第3段階の実装

更新日：2026-10-05

## 今回追加したもの

Security側のログイン・診断APIと画面を実装し、ローカルSecurity DBへ2つの追加マイグレーションを適用済みです。NAGeCen本体側から、ローカル実ログイン、Securityログアウト、同じ本体アカウントでの再ログイン成功との報告を受けました。Security画面の再読み込み後のログイン維持は、画面改装後に確認します。この実通信はこの作業中にこちらでは再実行していません。

- `backend/app/account_login/`：既存handoffと別の認証API、設定・署名・期限検証、利用者・セッション管理。
- `database/20261004_add_security_account_login.sql`：既存データを消さない追加マイグレーション。
- `database/schema.sql`：新規DB用にも同じ認証テーブルを追加。
- `backend/app/account_login/access.py` と既存診断ルート：新認証を有効にした場合のログイン検証・本人のデータだけへのアクセス制限。
- `database/20261004_add_diagnostic_account_ownership.sql`：確認キー・管理権限確認済み対象・診断ジョブへ利用者IDを追加。旧データの利用者は補完しません。
- `compose.yaml` と `.env.example`：ローカル用の新設定名を追加。実際の `.env` は変更していません。
- `backend/tests/test_account_login*.py`：単体、実PostgreSQL、模擬本体HTTPサーバー、実Redisのテスト。
- `backend/tests/test_account_diagnostic_access.py`：実API・専用PostgreSQLによる本人限定・期限切れ・CSRF・移行前後のテスト。
- `frontend/src/account-login/`：ログイン案内・戻り処理・セッション確認・ログアウト・期限切れ・表示専用プレビュー。
- `frontend/src/main.jsx`・`App.jsx`・`LandingPage.jsx`：既定無効の新入口、本人の診断フォームへの接続、メニュー表示。従来の動作は維持。
- `frontend/tests/account-login.test.mjs`：通信・callbackの単体テスト。
- `frontend/tests/account-login.browser-check.mjs`：表示と模擬ログインのブラウザ回帰テスト。Playwrightは別途テスト用に用意し、プロジェクト依存には追加していません。

本番設定は変更していません。認証用と診断所有者用のマイグレーションをローカルSecurity DBへ適用し、適用前に作成したGit管理外バックアップを検証済みです。古い診断結果14件は利用者に紐づかない記録として削除し、確認キーと対象サイトの記録は保持しています。従来モードのAPI・handoff・Webhook・戻り先は維持しています。

## まだ有効化しない

`SECURITY_ACCOUNT_LOGIN_ENABLED` は既定falseです。無効時の新APIは、DBへ接続する前に503を返します。
バックエンドは明示的な `APP_ENV=development` の場合だけ実行可能で、本番などの環境では有効化フラグがtrueでも新APIと新認証モードの診断APIを拒否します。
フロントも `VITE_SECURITY_ACCOUNT_LOGIN_ENABLED=false` が既定です。Vite開発モードとフロントのtrue設定が両方揃った場合だけ新入口を利用できます。本番ビルドではフロントのフラグをtrueにしても有効になりません。

保護APIと対象・結果のアカウント紐づけは第2段階で追加しました。現在のローカル開発環境では、Security側のログイン機能フラグが有効です。本体側フラグも本体担当から無効と聞いていましたが、その後のローカル実ログイン成功報告を受けています。現在値は本体側で確認してください。
callback画面は第3段階で追加しました。再読み込み後のセッション維持と拒否ケースを確認します。本番有効化は別途行わず、ログ対策・旧handoff導線の復帰確認も引き続き必要です。

ローカルSecurity DBには、認証用の `20261004_add_security_account_login.sql`、続いて対象・ジョブ用の `20261004_add_diagnostic_account_ownership.sql` を適用済みです。`schema.sql` は新規DB向けで、稼働中DBの全体置き換えには使いません。

## 新APIの形式

新APIのエラーは `{"status":"error","code":"...","message":"..."}` です。応答には `Cache-Control: no-store` と `Referrer-Policy: no-referrer` を付けます。
POSTはSecurityフロントのOriginとの完全一致と `application/json` を必須にし、本文は8KiB以内、未知の項目や不正JSONを拒否します。

### ログイン開始

`POST /api/auth/nagecen/start`、本文は `{}`。
200で `{"authorization_url":"本体の専用入口URLと開始クエリ"}` を返し、HttpOnlyの開始Cookieを発行します。
本体へ渡す項目は合意済みの `client_id`、`state`、`code_challenge`、`code_challenge_method=S256` だけです。

新しく開始すると、同じ開始Cookieに属する以前の試行を中止します。別タブの古い試行はやり直しになります。
開始APIには送信元単位の20回／分の制限を設けています。これは診断回数や課金上限とは別です。送信元IPはそのままDBに保存せず、用途を分けたHMACの値を保存します。プロキシ経由の送信元判定と適切な上限は、本番公開前に確認します。

### ログイン完了・中止

`POST /api/auth/nagecen/complete`。

- 完了：`{"state":"43文字の開始時state","code":"43文字の本体発行コード"}`。
- 本体で中止：`{"state":"43文字の開始時state","error":"access_denied"}`。

開始CookieとDB上のstate・期限・未使用状態を照合し、DBで一度限りの交換権を確保してから本体へ照会します。
PKCE verifierは永続DBに保存せず、既存の非永続Redisへ別のキー名で保存し、10分のTTLとGETDELによる一度限りの取得を適用します。Redisで情報が期限切れ・消失した場合は認証しません。

本体へは合意済みの生のJSONバイト列をHMAC署名して送ります。TLS検証を無効にせず、リダイレクトや自動再送を行いません。応答のissuer・request ID・audience・UUID v4・時刻・項目を照合します。

- 成功200：`{"status":"success","redirect_path":"/check"}` と、新しいSecurity専用のHttpOnlyセッションCookie。
- 中止200：`{"status":"cancelled","redirect_path":"/"}`。新しいセッションは作りません。

どちらも開始Cookieを削除します。接続障害や交換失敗後は、同じ試行を再送せず開始からやり直します。
再ログイン成功時は同じブラウザの旧Securityセッションを失効させます。他端末の本人のセッションは勝手に失効させません。

### ログイン状態

`GET /api/auth/session`。

- 未ログイン・期限切れ：200 `{"authenticated":false}`。
- ログイン中：200 `{"authenticated":true,"account_id":"Security内部UUID","expires_at":"現在の有効期限をUTCのZ形式で表した日時"}`。

`account_id` は本体の `subject` とは別のSecurity内部IDです。セッション秘密値や本体UUIDを返しません。
最大8時間と無操作1時間をサーバー側で確認します。状態確認のポーリングだけでは無操作期限を延長しません。
保護APIでは毎回セッションを検証します。GETによる結果のポーリング・状態確認では無操作期限を延長せず、許可されたOriginから本人が行うPOSTで最終利用日時を更新します。

### ログアウト

`POST /api/auth/logout`、本文は `{}`。
200 `{"status":"success","authenticated":false}`。SecurityのセッションをDBで失効させ、進行中の開始試行も中止し、Cookieを削除します。
コード交換中にログアウトした場合も、その交換の完了でセッションを作れないようにしています。本体のセッションには触れません。

## 第2段階：診断APIの本人限定

新認証モードでは、次のAPIをサーバー側で保護します。UIを隠すだけの制限ではありません。

- `POST /api/url-validation`
- `POST /api/site-verifications`
- `POST /api/site-verifications/{id}/confirm`
- `GET /api/scan-jobs/levels`
- `POST /api/scan-jobs`
- `GET /api/scan-jobs/{id}`
- `POST /api/scan-jobs/{id}/cancel`

診断用のDB依存処理・URL検証・対象サイト取得・本文のモデル検証より前に、専用CookieとDBのセッション・issuer・停止状態・期限を照合します。未ログインや失効時は401です。POSTはフロントOriginの完全一致とJSONを必須にし、8KiBまで、重複キーや不正JSONは拒否します。中止APIも `Content-Type: application/json` と `{}` を送ります。入力検証エラーで確認トークン・診断用パスワードなどの入力をそのまま応答へ出さないようにします。

確認キー・確認済み対象・ジョブの `account_id` は、リクエスト本文ではなく検証したセッションから設定します。本人のIDを条件にしてDB検索し、別人や旧データのIDを知っていても確認・診断・閲覧・中止できません。見つからないジョブと別人のジョブは同じ404です。他人や旧データの確認済み対象を使った診断作成は、存在しない対象と同じ既存の422応答になります。

DBでも、対象の利用者と確認キーの利用者、ジョブの利用者と対象の利用者が一致することを検証します。一度記録した利用者の付け替えは拒否します。Workerによる進捗・結果の更新は利用者を変更しないため、そのまま動かせます。本人でも開始済みの診断は中止できず、従来の409応答を維持します。キュー上限も従来どおり全利用者合算で、回数制限・料金設計とは別です。

### 旧データ・handoffの扱い

- 旧データの `account_id` はNULLのまま残します。本体の整数ID・旧owner_subject・メール等から推測して利用者を補完しません。
- 新認証モードで旧データを使う場合は、新たに管理権限確認からやり直します。旧handoff Cookieだけでは新認証モードに入れません。
- 新認証モードでは古いhandoff Cookieがブラウザに残っていても、新しい対象をプロダクトへ紐づけず、結果を本体へ自動送信しません。
- 従来のhandoff作成・交換・セッションAPI自体は変更しません。従来モードのプロダクト連携・Webhookも維持します。NAGeCen本体から新ログインのローカル実通信成功との報告はありますが、旧プロダクトhandoffから新ログインへ進んだ場合の復帰は別途確認が必要です。
- フラグ無効・DB未移行の場合でも、従来のNULL利用者データで診断できます。一方、新認証モードで作った利用者付きの対象や結果は、フラグを無効にしても匿名に公開せず、取得・中止等を拒否します。

履歴一覧API・画面は今回未追加です。将来の一覧は同じ利用者IDを条件に検索します。回数制限・課金・バッジも未実装です。

## 第3段階：ログイン画面と診断入口

### 見た目だけ確認する

通常の開発サーバーが5174番で動いていれば、`http://localhost:5174/preview/account-login` で確認します。従来の `/preview/top` の末尾にも、このプレビューへのリンクがあります。

トップの「ログイン」と「NAGeCenアカウントでログインして始める」から、案内画面を確認できます。画面上部の選択欄で、ログイン後・期限切れ・本体から戻る途中・中止・ログアウト後・接続エラーも表示できます。このプレビューは認証APIも診断APIも呼び出さず、ログインしたように診断処理を動かす機能はありません。ログイン・診断開始ボタンの一部は確認用として無効です。

### ローカル実接続用の入口

開発モードでフロントのフラグをtrueにした場合は、次を使用します。バックエンドの同名用途のフラグと設定・追加DBが揃っていない場合、診断フォームを開かず接続エラーを表示します。

| パス | 役割 |
| --- | --- |
| `/` | トップ。未ログインは案内へ、ログイン済みは診断へ進む |
| `/login` | 本体へ移動する前の説明。Securityのパスワード入力欄は作らない |
| `/auth/nagecen/callback` | 本体から戻り、コードを交換して専用セッションを確認する |
| `/check` | セッション確認後にだけ既存の診断フォームを開く |

本体へ移動するURLはサーバーから受け取りますが、フロントでも設定された本体入口のorigin・path・4つの合意済みクエリ項目を照合します。HTTPリダイレクトや未知の戻り先へは進みません。Cookie付きで開始・完了・状態・ログアウトのAPIを呼び出し、POSTはJSONです。共有鍵・本体パスワード・メールアドレスはフロントに渡しません。

`VITE_NAGECEN_LOGIN_AUTHORIZE_URL` は秘密ではない本体入口URLで、バックエンドの `NAGECEN_LOGIN_AUTHORIZE_URL` と一致させます。Composeでは後者からフロントへ渡します。直接Viteを起動する場合の初期値は `http://localhost:5173/nagecen/security-login` です。新認証の有効化にはフロントとバックエンドの両フラグが必要です。現時点ではローカル環境だけで有効化しています。

callbackのcode/stateはモジュール内で受け取り、Reactの状態やブラウザストレージに保存せず、React表示前にURLのクエリ・フラグメント・history stateを除きます。無効モードや不正callbackでもURLを清掃します。完了POSTは共有する1つのPromiseで1回だけ実行し、開発時のStrictModeによるEffect再実行でも二重交換しません。失敗時は同じコードを自動再送せず、開始からやり直します。成功後にサーバーのセッションを再確認して、固定の `/check` へ進みます。

ログアウト・期限切れ・401応答・別タブのアカウント変更が確認された際は、診断フォームと結果をアンマウントして入力を消します。本人IDが変わった場合も以前の表示を引き継ぎません。新モードでは診断ジョブIDをlocalStorageへ保存・復元しません。結果のDB削除やWorkerの中止は行いません。

GETによる状態確認は無操作期限を延ばしません。初回、1分間隔、画面への復帰、別タブのログイン・ログアウト通知で再確認し、応答に含まれる期限でも表示を閉じます。別タブへの通知には秘密値や利用者IDを含めません。停止の即時反映を保証する機構ではなく、認可の根拠は各APIでのサーバー側検証です。BroadcastChannel非対応のブラウザでは、定期確認・画面復帰で確認します。

従来の `/integrations/nagecen` はフラグ無効時には元のままです。新フラグを有効にした開発モードでは「切り替え準備中」と表示し、旧プロダクト連携を自動で独立アカウントへ付け替えません。旧導線の扱いとログイン後の復帰は本体側との調整が必要で、この状態で本番へ移行してはいけません。

フラグ無効時に新入口へアクセスした場合は「準備中」と表示し、認証・診断APIを呼び出しません。通常のトップや既存handoffはこれまでどおりです。

## 検証と未確認の区別

第1段階では既存テストを含む186件が成功しました。第2段階の2026-10-04の最終確認では、既存テストを含む **241件すべて成功**。実PostgreSQLでのマイグレーション・同時交換・セッション期限、模擬HTTP本体APIへの署名付き通信、実RedisでのTTL・一度限り取得に加え、別人のID・失効Cookie・偽装Origin・本文への利用者ID注入・パスワード入力のエラー・旧DB移行前後を確認しました。`git diff --check` と、設定例による `docker compose --env-file .env.example config --quiet` も成功しました。

専用の一時PostgreSQL、Redis、テストコンテナを使います。実際のSecurity・本体DBのURLへフォールバックするテストはありません。
DBテスト用の指定は `ACCOUNT_LOGIN_TEST_DATABASE_URL`、Redisテスト用の指定は `ACCOUNT_LOGIN_TEST_REDIS_URL`。どちらも専用テスト環境のみを指定します。

第3段階ではフロントの単体テスト **40件すべて成功**。本番ビルド、フロントフラグをtrueにした本番ビルド、`git diff --check`、設定例でのCompose検証も成功しました。
許可済みのPlaywrightと新しいChromeプロファイルで、PC1440px・スマホ390pxそれぞれ8画面、合計16画面を確認し、横はみ出しなし・表示プレビューのAPI呼び出し0件を確認しました。模擬APIで、本体への移動、callbackの一度限り交換、中止・不正callback、Cookie付きの診断API、401後の入力消去、別タブのアカウント変更・ログアウト、接続エラーと再確認、旧導線の準備中表示、無効モードでのURL清掃を確認し、ブラウザのJavaScriptエラーは0件でした。

NAGeCen本体側から、ローカルPHPを含む実ログイン往復とログアウト・再ログインの成功報告を受けています。今回こちらで実行した自動テストはNAGeCen本体への通信をモックに置き換えたものです。本番の検証ではありません。

2026-10-05にログイン連携・診断アクセスの対象テストを専用の一時PostgreSQLと読み取り専用ソースマウントで実施し、**147件成功、1件スキップ**。確認対象には期限切れ・使用済みコードや署名エラーを表す本体APIの拒否応答（モック）、不正state、期限切れ・消失・不一致のPKCE、ログイン試行の再利用、別アカウントの診断結果アクセス拒否を含みます。スキップは専用Redisを必要とするRedis実接続テストです。読み取り専用マウントのためpytest cacheの書込み警告が2件出ましたが、テスト結果には影響していません。一時DBは終了後に削除しました。

Security画面を改装した後に、実本体を使った再読み込み後のログイン維持と、期限切れコード・コード再利用・不正state・不正署名・PKCE不一致が拒否されることを改めて確認します。
検証で実際の診断・ZAP・Webhook送信は行いません。

再確認は `frontend/` で `npm run test:account-login` と `npm run build`。ブラウザ回帰テストは、通常の開発サーバー5174番と、新フロントフラグだけをtrueにした隔離確認用サーバー5175番を用意します。Playwrightのモジュールをテスト用の一時フォルダに用意し、`ACCOUNT_LOGIN_PLAYWRIGHT_MODULE` にその `index.mjs`、`ACCOUNT_LOGIN_BROWSER_ARTIFACT_DIR` に一時保存先を設定して `npm run test:account-login:browser` を実行します。MacのChrome以外を使う場合は `ACCOUNT_LOGIN_BROWSER_EXECUTABLE` に実行ファイルを指定します。APIと本体はすべてローカルの模擬応答へ差し替えるテストで、実際のバックエンド起動や共有鍵は不要です。

保存期間（詳細90日・履歴1年・調査ログ14日）の自動削除は今回未実装です。
期限切れの認証メタデータやセッションの定期清掃、本番ログ・プロキシの設定確認も後続の作業として残っています。PKCEの秘密値にはRedisのTTLが既にあります。

## 次の段階

1. 今回の画面を利用者に確認してもらう。
2. 本体側へ `account_uuid`、専用入口、コード発行・交換APIのローカル実装を依頼する。旧handoffからの再ログイン・復帰の扱いも合意して実装する。
3. 追加マイグレーションと専用設定を、承認されたローカル環境へ適用し、双方をつないで確認する。
4. 履歴一覧と保存期限、ログ対策・定期清掃を追加する。
5. 本番ログ、各APIの保護、既存導線の回帰確認が済んだ後に、本番反映を別途相談する。

設計の共通契約は [ログイン連携仕様](nagecen-account-login-contract.md)。セッションのサーバー側失効とCookie管理は [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)、PKCEの計算は [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) を参照しています。
本人のデータに限定した検索は [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)、Origin検証は [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) を参照しています。
開発時のEffect再実行は [React StrictMode](https://react.dev/reference/react/StrictMode)、Cookieを含む送信は [MDN Request.credentials](https://developer.mozilla.org/en-US/docs/Web/API/Request/credentials) を参照しています。
