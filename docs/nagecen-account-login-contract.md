# NAGeCenアカウントでSecurityを利用するための連携仕様案

作成日：2026-10-04

**状態：利用者と本体側で基本契約に合意済み。Security側の認証API・診断API保護・利用者紐づけ・DB追加ファイル・ログイン画面を実装し、画面とブラウザ動作は模擬APIで確認済み。すべて初期設定は無効で、開発環境限定です。履歴一覧・本体APIとの実通信・本番有効化は未完了です。**
既存のプロダクトhandoffの仕様書ではありません。本体側の最終確認結果に基づき、UUIDのDB項目・移行方針と運用上の注意点を反映しました。実装中に契約を変える場合は、双方で変更点を確認します。
本番VPSの設定は今回確認・変更していません。秘密値はこの資料に含めません。
検査履歴・結果の保存期間は、利用者との相談で合意した方針を第10節に記載します。
第1〜第3段階の実装内容・新APIの応答・未完了事項は [Security側の実装メモ](security-account-login-implementation.md) を参照してください。既存DBへ追加マイグレーションはまだ適用していません。

## 1. 目的と変更範囲

- Securityを使う利用者は、NAGeCenアカウントでログインする。
- NAGeCenへのプロダクト登録、下書き保存、本人所有のプロダクトとの照合は要求しない。
- 利用者はSecurity側で診断専用のテストURLを入力する。
- URLへ確認タグを設置できることの確認は、Security側で引き続き行う。アカウントのログインとは別の確認である。
- 将来の検査履歴・利用回数は、検証済みのアカウントに紐づける。今回、回数・料金・バッジを決めたり実装したりしない。
- パスワード、メールアドレス、本体のセッションCookieをSecurityへ渡さない。

既存のプロダクトhandoff/API/Webhook/戻り先は、削除・意味変更・流用しない。
新しいアカウント連携で架空のproduct IDを発行したり、空の下書きを保存したりしない。
検査結果をプロダクトへ自動反映するWebhookも、今回のアカウント連携では送らない。

## 2. 現在のコードで確認したこと

- 従来の `/preview/top` はデザイン確認用で、CTAは本体の `/nagecen/login` への単純リンク。第3段階で別の `/preview/account-login` と、新フラグで有効になる開発専用のトップ・ログイン案内・callback・診断入口を追加した。既存の導線はまだ切り替えていない。
- 本体の `frontend/src/auth/ProtectedRoute.jsx` は、ログイン前のアプリ内パスとクエリを `location.state.from` に保存する。
- 本体の `frontend/src/pages/Login.jsx` は、ログイン・新規登録後に `location.state.from`、なければ `/mypage` へ移動する。
- 本体の `backend/api/auth.php` にCookieセッション、CSRF検証、有効な利用者の照合処理がある。
- 本体の `backend/api/create_security_handoff.php` はproduct ID、DBの所有者とURLを必要とする。
- Securityの `backend/app/integrations/nagecen.py` もproduct ID・URL・所有者を必要とする。既存のhandoff Cookieはプロダクト連携用で、新しいアカウントセッションではない。
- 従来の診断作成APIはタグによるサイト管理権限確認を要求する。第2段階で独立アカウントの保護処理を追加したが、初期設定は無効のままで、稼働中の本番導線は切り替えていない。

## 3. 利用者から見た流れ

1. Securityトップで「NAGeCenアカウントでログインして始める」を押す。
2. Securityがログイン開始情報をサーバーに保存し、本体の専用入口へ移動する。
3. 未ログインなら本体の既存ログイン／新規登録を利用する。
4. 本体で「このアカウントでNAGeCen Securityへ進む」を確認する。すでにログイン済みでも、無条件で別サービスへ飛ばさない。
5. 本体が短時間・一度限りの確認コードを発行し、Securityへ戻す。
6. Securityサーバーが本体サーバーへコードを照会する。正しい利用者と確認できた場合だけ、Security専用のログイン状態を作る。
7. Securityの診断準備・テストURL入力へ進む。ここではまだ診断を開始しない。

「プロダクトの所有者確認」はこの流れに入れない。タグの設置確認は、対象サイトの管理権限として別途実施する。

## 4. 合意した方式

短時間の確認コードをサーバー間で交換する方式にする。
開始したブラウザとの照合に `state`、確認コードの盗用対策にPKCEのS256を使用する。
本体の確認コード照会APIへのアクセスは、用途を分けたHMAC共有鍵で認証する。
本体側の既存機能確認では、OAuth/OIDC基盤はなく、独自のプロダクトhandoffがある構成。本契約はその前提で新設する。
この方式を採用するだけでOAuth/OIDC準拠、または安全性の保証を主張しない。

### Security側（新設案）

| 入口 | 役割 |
| --- | --- |
| `POST /api/auth/nagecen/start` | 開始情報とブラウザ照合用Cookieを作り、`authorization_url` を返す |
| `/auth/nagecen/callback` | 本体からの `code` と `state`、または中止情報を受け取るフロント画面 |
| `POST /api/auth/nagecen/complete` | 開始Cookie・stateを照合し、サーバー間でコードを交換する |
| `GET /api/auth/session` | ログイン状態のみ確認。セッションの秘密値は返さない |
| `POST /api/auth/logout` | Security側のセッションをサーバーで失効させる |
| `/check` | ログイン済み利用者の診断準備・テストURL入力画面 |

`start` は許可したSecurityフロントのOriginからのJSON POSTのみ受け付ける。
ログイン開始前の状態と認証後のセッションは分け、開始時のCookieを認証済みCookieへ昇格させない。
開始情報は10分で失効する案。stateとPKCE verifierは各32バイトの暗号学的乱数をbase64url化する。
stateは保存時にハッシュ化し、PKCE verifierはSecurityサーバーだけに保存する。
ブラウザ照合Cookieも暗号学的乱数を使用し、保存側ではハッシュ化する。
単純なstateの有無だけで受け入れず、同じ開始Cookieに属する未使用・未期限切れの試行か照合する。
複数タブの扱いは、試行を1件に制限するか複数保持するかを実装時に明示してテストする。

### 本体側（新設案）

| 入口 | 役割 |
| --- | --- |
| `/nagecen/security-login` | Security専用入口。既存のProtectedRouteでログイン／新規登録へ案内し、この入口へ戻す |
| `POST /backend/api/create_security_login_code.php` | 有効な本体ログイン＋CSRFを確認し、プロダクトとは無関係なコードを発行する |
| `POST /backend/api/exchange_security_login_code.php` | Securityサーバーから署名付きで受けたコードを一度だけ交換する |

上のAPIパスは本番の `/nagecen` 配下では `/nagecen/backend/api/...`。
現在のローカルPHPコンテナでは `/api/...`。新設案を既存の本番APIと混同しない。

## 5. ブラウザの往復とコード発行

本体の専用入口へ渡すクエリは次の4項目だけにする。

```text
client_id=nagecen-security
state=<43文字のbase64url>
code_challenge=<43文字のbase64url>
code_challenge_method=S256
```

- PKCE challengeは `BASE64URL(SHA256(ASCII(code_verifier)))`、末尾の `=` は省く。
- 本体は `client_id`、state/challengeの文字種・長さ、S256のみであることを検証する。省略やplainへの変更は拒否する。
- 任意の `return_url` / `redirect_uri` をクエリから採用しない。client IDに対する完全一致のcallback URLをサーバー設定で固定する。
- 本体の入口を保護し、ログイン後もクエリを保って戻す。再読込・新規登録もテストする。
- ログイン中の利用者はサーバーのPHPセッションと有効なusersレコードから取得する。`user_id` / `subject` をブラウザ入力から採用しない。
- コード発行は、利用者が「Securityへ進む」を押した後のJSON POST（上の4項目＋既存の `X-CSRF-Token`）で行う。Originも本体の許可Originと照合する。
- 本体のサーバー設定が未完了なら503。外部へ飛ばさず、再試行・本体へ戻る操作を表示する。

コード発行成功の応答案（201）：

```json
{
  "status": "success",
  "redirect_url": "https://nagecen-security.ucu4-lab.mydns.jp/auth/nagecen/callback?code=EXAMPLE_ONLY&state=EXAMPLE_ONLY",
  "expires_at": "2026-10-04T03:02:00Z"
}
```

`EXAMPLE_ONLY` は説明用の置換箇所で、実際のcode/stateはそれぞれ43文字の乱数。
確認コードは本体で32バイト乱数から生成し、DBにはSHA-256ハッシュだけを保存する。有効期限は発行から2分の案。
DBにclient ID、固定callback URL、stateのハッシュ、PKCE challenge、利用者ID、codeの一意なUUID、作成・失効・使用日時を保持する。
完了時のstateは、コード発行要求で受けた値をそのまま返す。

成功時はSecurity callbackへ `code` と `state` だけをクエリで渡す。
Security callbackは外部画像・解析タグなどを読まず、受け取ったクエリを速やかに履歴から除いてから完了APIを呼ぶ。
本体とSecurityの当該画面/APIには `Cache-Control: no-store` と `Referrer-Policy: no-referrer` を適用する。
コード、state、verifier、署名、CookieをURLアクセスログ・エラーログ・テスト出力に記録しない。配信基盤のログ設定も本番反映前の確認対象。
ブラウザ履歴の除去だけでは、callbackに届くクエリのサーバー側記録は防げない。本体とSecurityそれぞれのWebサーバー・プロキシ・APIサーバー・アプリケーション・解析ツールについて、認証用URLのクエリと認証用POST本文を記録しないことを確認する。SecurityのCaddyとバックエンドのアクセスログも対象にし、リクエストパスやステータスなど秘密を含まない項目だけを残す。実際の本番ログ設定は未確認・未変更で、本番有効化前の必須確認項目とする。

中止時の戻り先は固定callbackに `error=access_denied&state=<開始時state>` を付ける。
不正な開始パラメータは本体で止める。ユーザー入力のURLへエラー情報を送らない。

## 6. サーバー間のコード交換

Securityはブラウザの開始Cookie・state・未使用期限を確認した後だけ、設定済みの本体交換APIへPOSTする。
ブラウザから本体交換APIへ直接アクセスしない。PHPセッションCookieとブラウザ用CSRFトークンはこの交換に使用しない。

交換リクエスト案：

```json
{
  "version": "1",
  "request_id": "11111111-1111-4111-8111-111111111111",
  "client_id": "nagecen-security",
  "code": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  "redirect_uri": "https://nagecen-security.ucu4-lab.mydns.jp/auth/nagecen/callback"
}
```

上のcode/verifierは試験・説明用で実利用不可。サーバーは既知項目だけを受け付け、本文は最大8KiBとする案。
ブラウザから受けた任意の交換先URLを使わず、Securityサーバー内の固定設定を使う。
本番はHTTPS、TLS検証必須、リダイレクト追従なし。タイムアウトを設定する。
ローカル開発のHTTP例外は明示した開発環境の固定接続先だけに限定する。

署名ヘッダー（すべて新設案）：

```text
X-Security-Login-Key-Id: <設定済みの共有鍵を識別するラベル。秘密値ではない>
X-Security-Login-Timestamp: <Unix秒・10進文字列>
X-Security-Login-Signature: sha256=<小文字hexのHMAC-SHA256>
```

署名対象のバイト列：

```text
ASCII("nagecen-security-login-v1.") + ASCII(timestamp) + ASCII(".") + raw_request_body
```

本文はUTF-8 JSON。送信する本文を一度だけ生成し、実際に送る同じバイト列を署名する。
本体は受け取った生の本文で検証する。空白・改行・キー順を変えて再JSON化しない。
署名の許容時差は±60秒の案。サーバー時刻の同期が前提。
専用共有鍵を使用し、既存のhandoff/Webhook用鍵と兼用しない。
定数時間比較で署名を検証し、その後でJSONを解釈する。
request IDはUUID v4。署名済みrequest IDの再利用を少なくとも5分拒否する。

本体の交換処理はトランザクション内でコードをロックし、次をすべて検証する。

- 正しい署名・専用鍵ID・時刻・未使用request ID。
- 有効期限内・未使用のcode、正しいclient ID、登録済みcallback URLとの完全一致。
- 保存済みchallengeとS256(verifier)の一致。challenge/verifierがないコード交換を受け付けない。
- その利用者が現在も有効であること。過去の発行時の値だけでアカウント停止を見逃さない。

成功した交換だけがcodeを使用済みにする。同時交換は1件だけ成功し、再送で2つのセッションを作らない。
タイムアウトなどで消費結果が不明なら同じcodeの自動再送に依存せず、ログイン開始からやり直す。
Securityの開始試行もロックして重複完了を防ぎ、成功時は新しいSecurityセッションIDを生成する。

交換成功の応答案（200）：

```json
{
  "status": "success",
  "version": "1",
  "request_id": "11111111-1111-4111-8111-111111111111",
  "login_id": "22222222-2222-4222-8222-222222222222",
  "issuer": "https://ucu4.sakura.ne.jp/nagecen/",
  "audience": "nagecen-security",
  "subject": "33333333-3333-4333-8333-333333333333",
  "issued_at": "2026-10-04T03:00:00Z",
  "validated_at": "2026-10-04T03:00:15Z"
}
```

SecurityはTLS検証済みの固定交換先からの応答だけを信頼し、status/version/request ID/issuer/audienceと応答形式を照合する。
`subject` は、本体の利用者に追加する `users.account_uuid` の文字列とする（双方合意済み）。当初のusers.idの10進文字列案は採用しない。
UUID v4を使用し、ハイフン付き・小文字の標準表記で返す。上のUUIDは説明用の固定値で、実利用者へ割り当てない。
本体の既存users.idと既存の参照関係は変更せず、UUIDを別項目で追加する。既存利用者にも一度だけ割り当て、新規利用者には登録時に割り当てる。保存後はログインやコード発行のたびに作り直さず、異なる利用者へ再割当てしない。

本体側のMySQLでは最終的に `CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE` とする。PHPで暗号学的乱数からUUID v4を生成する。既存DBを初期化せず、次の段階で移行する。

1. nullableの `account_uuid` 列と一意インデックスを追加する。
2. 新規登録時にUUIDを保存する処理を用意する。
3. 停止中を含む既存利用者すべてへ、NULLのものだけ一度ずつUUIDを割り当てる。既存UUIDを上書きしない。
4. NULL・重複・UUID v4の形式を確認後にNOT NULL制約を付ける。
5. 移行と検証が済むまでアカウント連携を有効化しない。

UUIDの非再利用は運用上も守る。手動作業・データ移行・削除後の登録で過去のUUIDを別人へコピーせず、新しいアカウントには新しいUUIDを発行する。将来アカウント削除を追加する際も、削除した利用者のUUIDを再割当てしない。Security側の過去の履歴を、同じメールアドレスや整数IDを理由に別アカウントへ付け替えない。
UUIDは利用者の識別番号であり、認証用の秘密値やセッションIDではない。UUIDを知っていることだけでログインを成立させない。
`issued_at` はコード発行日時であり、パスワードを入力した日時ではない。`validated_at` はコード交換日時。
Security内の利用者キーは `(issuer, subject)`。ローカルissuerは本体のローカルURLとし、本番の利用者と混ぜない。
メール、表示名、プロダクトID、検査結果、長期access tokenは返さない。

エラーは `{"status":"error","code":"...","message":"..."}` に統一する案。

| 状況 | HTTP / code案 |
| --- | --- |
| 不正JSON・パラメータ | 400 / `invalid_request` |
| 署名なし・不正・専用鍵ID不一致 | 401 / `invalid_client` |
| 署名時刻の期限切れ | 401 / `request_expired` |
| 未ログイン（コード発行時） | 401 / `login_required` |
| CSRF・Origin不一致（コード発行時） | 403 / `csrf_failed` |
| 不明・期限切れ・使用済みcode、PKCE不一致、無効利用者 | 400 / `invalid_grant`（理由を細分化して公開しない） |
| request IDの再使用 | 409 / `request_replayed` |
| 制限超過 | 429 / `rate_limited` |
| 設定不足・接続先の障害 | 503 / `login_unavailable` |

Securityの開始Cookie/state不一致は403、開始期限切れは410、未ログインの保護APIは401。
利用者向けには再ログイン・Securityトップへ戻る導線を用意し、技術的な秘密や例外を表示しない。

## 7. Securityのログイン状態と保護範囲

- 本番Cookieは `__Host-nagecen_security_account_session`（新設案）、Secure/HttpOnly/SameSite=Lax/Path=/、Domain指定なし。
- 開発時はSecureなしの別名Cookieを使用できるが、localhostと127.0.0.1を混用しない。ポートだけではCookieが分かれないため、本体と異なる名前にする。
- DBにはセッションIDのハッシュ、内部account ID、作成・最終利用・失効・取消日時を保持する。セッション秘密をlocalStorageやURLに保存しない。
- 絶対期限8時間、操作なし1時間で失効する初期方針（双方合意済み）。上限はサーバーで管理する。操作していても絶対期限は延長しない。長期ログイン／refresh tokenは今回追加しない。
- `complete` と `logout` はJSON POST＋厳密な許可Origin検証。認証後の他の更新APIもCSRF対策を実装し、SameSite属性だけに頼らない。
- 公開LPと認証開始はログイン前も利用可能。URL確認、管理権限確認の発行・照合、診断の作成・取得・中止、履歴はサーバー側でログインを必須にする。
- 検証対象・タグ確認・診断job・履歴を内部account IDへ紐づけ、IDを知っていても他人のデータへアクセスできないようにする。
- 利用回数は将来サーバーでこのaccount ID単位に管理する。URLやCookieの自己申告IDで判定しない。
- 既存のプロダクトhandoff Cookieだけを新しいアカウント認証の証明として扱わない。
- Securityからログアウトしても本体からはログアウトしないことを明記する。単一ログアウト、アカウント停止の即時通知は別途設計が必要。
- 本体側はコード発行・交換時に有効利用者を再確認する。初期版では本体アカウント停止の即時通知を実装しない。停止後も既存Securityセッションが上記期限まで利用できる可能性があることを利用者に説明し、この初期方針は双方合意済み。利用者向け説明と受け入れテストにも明示する。即時失効の仕組みは将来別途設計する。

本体側の最終確認で、次の2点に合意した。

1. 長期の利用者識別には、本体の既存整数IDではなく、追加する不変UUIDを採用する。
2. 初期版ではアカウント停止の即時通知を設けず、既存Securityセッションは最大8時間／無操作1時間で失効する。

## 8. 設定名と接続先（新設・未有効化）

双方共通の秘密設定：

```text
SECURITY_TO_NAGECEN_LOGIN_KEY_ID
SECURITY_TO_NAGECEN_LOGIN_HMAC_SECRET
```

この鍵はSecurityから本体の交換APIへの照会専用。32バイト以上の暗号学的乱数から作り、本番と開発で別にする。
秘密値はGit管理外のサーバー設定だけに置く。既存の2方向の共有鍵を上書きしない。

Security側の公開／サーバー設定案：

```text
SECURITY_ACCOUNT_LOGIN_ENABLED
NAGECEN_LOGIN_AUTHORIZE_URL
NAGECEN_LOGIN_EXCHANGE_URL
NAGECEN_ACCOUNT_ISSUER
```

本体側の設定案：

```text
NAGECEN_SECURITY_ACCOUNT_LOGIN_ENABLED
NAGECEN_SECURITY_LOGIN_CALLBACK_URL
NAGECEN_ACCOUNT_ISSUER
```

callbackの完全一致は、各環境のclient設定に紐づける。Security側も自分の設定済みcallbackからredirect_uriを作る。

| 用途 | ローカルの提案値 | 本番の提案値 |
| --- | --- | --- |
| 本体専用入口・ブラウザ向け | `http://localhost:5173/nagecen/security-login` | `https://ucu4.sakura.ne.jp/nagecen/security-login` |
| Security callback・ブラウザ向け | `http://localhost:5174/auth/nagecen/callback` | `https://nagecen-security.ucu4-lab.mydns.jp/auth/nagecen/callback` |
| 本体コード発行・ブラウザ向け | `http://localhost:8080/api/create_security_login_code.php` | `https://ucu4.sakura.ne.jp/nagecen/backend/api/create_security_login_code.php` |
| 本体コード交換・Securityコンテナ向け | `http://host.docker.internal:8080/api/exchange_security_login_code.php` | `https://ucu4.sakura.ne.jp/nagecen/backend/api/exchange_security_login_code.php` |

SecurityをDocker外から動かすローカル交換先は `http://localhost:8080/api/exchange_security_login_code.php`。
ここに列挙した本体API・ブラウザ画面はまだ新導線として稼働していない。Securityの認証APIも初期設定は無効で、第1段階は開発環境に限定する。起動ポート・配信パスは双方の実通信で確認する。
ローカルAPI呼び出しは `credentials: 'include'` と必要なCORSを双方で確認する。異なる本番ドメインで本体Cookieを共有する設計にはしない。

## 9. 分担と実装順序

1. 本体側との基本契約確認は完了。必要なUUID項目と移行方針、セッション期限、API・署名・設定名・接続先を本仕様で共有する。
2. Security側で認証開始・完了・セッション、DB、保護API、ローカルの入口を実装する。
3. 本体側で専用入口、コード発行・交換API、期限・一度限りのDB管理を実装する。本体側のチャットが担当する。
4. 両方のローカル環境をつないでテストする。新しい認証の有効化と、診断API保護は一緒に切り替え、UIだけでログイン必須に見せない。
5. 本番の有効化は別途承認後。既存の本体プロダクト連携から来る利用者もログインを必要とするため、旧導線の扱い・再ログイン後復帰を合意し、既存契約を黙って壊さない。

新フラグは既定falseとし、双方の実装が揃うまで本番のリンクや既存handoff/APIを切り替えない。
このファイルを作成しただけでは、ログイン必須・アクセス制限・回数制限は実施されない。

## 10. 検査履歴・結果の保存方針（合意済み・未実装）

Security側のDBで管理する。NAGeCen本体のDBを直接参照したり、同じDBへ保存したりしない。
ログイン連携では利用者の識別だけを行い、検査履歴・結果を本体へ渡さない。

| 保存するもの | 保存期間 | 内容 |
| --- | --- | --- |
| 詳細な検査結果 | 90日 | 指摘内容、改善案、検出箇所など |
| 検査履歴 | 1年 | 実施日、対象URL、完了・失敗などの状態、指摘件数 |
| 不具合調査用のログ | 14日 | 運営側が不具合を調べるための記録 |

- 詳細結果の期限が過ぎても履歴の期限内は一覧に残し、「詳細結果の保存期間が終了しました」と表示する。期限切れの詳細結果はAPIからも取得できないようにする。
- PC・スマホで同じアカウントにログインした場合も、同じ保存期間とアクセス制限を適用する。ログアウトやセッション失効で履歴を消さない。
- 履歴・結果の削除と、将来の利用回数管理は分ける。結果を削除しても検査回数の上限がリセットされないようにする。課金記録やセキュリティ監査記録の保存期間は、この不具合調査ログの14日と混同せず、別途決める。
- パスワード、認証コード、Cookie、トークン、共有鍵は履歴・結果・ログの長期保存対象にしない。対象URLの秘密値や検出内容に含まれる機密情報の除去も実装時に確認する。
- アカウントの識別情報・セッションの有効期限は、検査履歴の保存期間とは別に管理する。アカウント削除時の扱いは別途決める。
- 自動削除の処理、期間の起点、バックアップ内の保存期限、利用者への期限表示は、履歴機能の実装時に具体化する。詳細結果の自動削除は現時点では未実装で、今回の仕様更新によるデータ削除は行わない。

## 11. 最低限の受け入れテスト

- 未ログイン／ログイン済み／新規登録後それぞれで、専用入口からSecurityへ戻れる。プロダクト0件でも成功する。
- 通常の投稿・マイページ・ログイン後復帰に変更がない。古いhandoff/API/Webhookの回帰確認を行う。
- ログインや新規登録中の再読込、戻る、中止、開始期限切れで行き止まりにしない。
- 別ブラウザで開いたcallback、不正state、開始Cookieなし、PKCE不一致、任意callback URLを拒否する。
- コードの期限切れ・再利用・同時交換で認証を成立させない（同時の正規交換は1件だけ成功）。
- 不正署名、旧用途の鍵、期限切れ署名、同じrequest ID、本体アカウント停止、設定不足を拒否する。
- 未ログインで直接診断APIを呼べない。他人の対象ID／job IDで取得・中止・閲覧できない。
- ログアウト、セッション期限切れ、再ログイン後にも、別の利用者の結果が残らない。
- 既存利用者・新規利用者ともに不変UUIDを取得でき、再ログインで変わらない。UUIDの文字列だけを送っても認証できない。別アカウントへ履歴が引き継がれない。
- 本体のUUID移行を途中から再実行しても既存UUIDが変わらず、停止中の利用者にもUUIDがある。NULL・重複・形式不正が残った状態では新連携を有効化しない。
- 無操作1時間と絶対期限8時間をサーバー側で検証する。本体の停止利用者は新規コード発行・交換に失敗する。既存Securityセッションには初期方針どおり期限を適用する。
- 同じ利用者が別端末から再ログインしても、保存期間内の本人の履歴・詳細結果だけを確認できる。
- 詳細結果の期限切れと履歴の期限切れを別々に処理し、期限切れの詳細をAPIから取得できない。履歴・結果の削除で利用回数がリセットされない。
- code/state/verifier/署名/Cookie/共有鍵がログ・ブラウザ履歴・分析ツールへ残らない。
- callbackのクエリがWebサーバー・プロキシ・バックエンドのアクセスログにも残らないことを、秘密値ではない試験用データで確認する。本番配信基盤の確認が済むまで本番の新連携を有効化しない。
- 本体停止・照会タイムアウト時に認証成功と見せず、再試行へ戻せる。実際の診断は認証テストでは実行しない。

## 12. 設計上の参照資料

この案の期限・パス・設定名は、このプロジェクト用の提案値。
stateのブラウザ照合、PKCE、固定した戻り先という対策の根拠は [OWASP OAuth2 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)。
S256の計算は [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) を参照。
Cookie・サーバー側失効は [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)、更新処理のCSRF対策は [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) を参照。
