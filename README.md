# NAGeCen Security

NAGeCenに投稿するWebサービスを対象とした、初心者向けセキュリティ診断サービスです。

現在はMVPの第3段階として、診断候補URLの安全確認と、metaタグによるサイト所有確認を実装しています。診断機能とOWASP ZAPはまだ含まれていません。

## 必要なもの

- Docker Desktop
- Git

## 起動方法

```bash
docker compose up --build
```

起動後、以下を確認します。

- 画面: http://localhost:5174
- APIの動作確認: http://localhost:8000/health
- APIドキュメント: http://localhost:8000/docs
- PostgreSQL（ローカルDBクライアント用）: 127.0.0.1:5433

画面に「開発環境は正常です」と表示されれば、フロントエンドからバックエンドとデータベースまで接続できています。

画面のURL入力欄では、公開WebサイトのURLだけを受け付けます。URLの安全確認だけでは対象サイトへアクセスしません。

所有確認キーを発行した後、表示されたmetaタグを対象ページの`<head>`内へ設置して「設置したmetaタグを確認」を押すと、対象ページへ安全対策付きでアクセスしてタグを照合します。

- 確認キーの有効期限は30分です。
- 確認キーはデータベースへ平文保存せず、ハッシュ化して保存します。
- リダイレクト先は毎回URLとIPを再検査します。
- 最初に指定したホスト以外には移動しません。
- 取得するHTMLは最大1MB、通信時間は最大10秒です。

## 自動テスト

```bash
docker compose exec backend pytest -q
```

localhost、内部ネットワーク、認証情報付きURL、規定外ポート、危険なリダイレクトなどが拒否されることを確認します。

## 停止方法

起動中のターミナルで `Ctrl + C` を押した後、以下を実行します。

```bash
docker compose down
```

データベースの保存内容も削除して完全に初期化する場合だけ、次を使用します。

```bash
docker compose down --volumes
```

## 環境設定

通常のローカル確認では設定ファイルを作らなくても起動できます。値を変更したい場合は、`.env.example` を `.env` という名前でコピーして編集します。

`.env` はパスワードなどを含む可能性があるため、Gitには登録されません。

ローカル開発では、Security APIのCORSに以下の画面を許可しています。

- NAGeCen Security: `http://localhost:5174`
- NAGeCen本体: `http://localhost:5173`

CORSは、異なるポートの画面からAPIへ接続してよいかをブラウザへ伝える設定です。パスは含めないため、NAGeCen本体が`/nagecen/`配下にあっても許可値は`http://localhost:5173`です。

## Database Client JDBCから接続する

VS CodeのDatabase Client JDBCなどから、以下の内容で接続できます。

- 種類: PostgreSQL
- Host: `127.0.0.1`
- Port: `5433`
- Database: `nagecen_security`
- User: `nagecen_security`
- Password: `change-me-for-local-development`
- JDBC URL: `jdbc:postgresql://127.0.0.1:5433/nagecen_security`

DBポートはMac内の`127.0.0.1`だけに公開しており、外部ネットワークからは接続できません。
