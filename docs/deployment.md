# NAGeCen Security デプロイ手順

この文書は、ローカル開発環境とKAGOYA VPS本番環境を取り違えないための手順書です。

## 使い分け

### ローカル開発

普段の開発では、既存の `compose.yaml` を使用します。

```bash
docker compose up
```

`frontend/` と `backend/` のコードは、ローカル開発と本番環境で共通です。

### KAGOYA VPS本番環境

本番環境では、必ず `compose.production.yaml` と `.env.production` を明示します。

```bash
docker compose \
  -f compose.production.yaml \
  --env-file .env.production \
  up -d --build
```

## 本番用ファイル

| ファイル | 役割 |
| --- | --- |
| `compose.production.yaml` | 本番コンテナ全体の構成 |
| `backend/Dockerfile.production` | FastAPIの本番用イメージ |
| `frontend/Dockerfile.production` | ReactのビルドとCaddyの本番用イメージ |
| `Caddyfile` | HTTPS、API転送、React配信 |
| `.env.production.example` | 本番環境変数の見本 |
| `.env.production` | 本物の秘密値を含むVPS専用ファイル（Git管理外） |

## 現在の公開先

- Security: `https://nagecen-security.ucu4-lab.mydns.jp`
- NAGeCen本体: `https://ucu4.sakura.ne.jp/nagecen`
- KAGOYA VPS IPv4: `133.18.145.207`

## 初回デプロイの流れ

実際の作業では、次の項目を一つずつ確認して進めます。

1. ローカルでテストと本番ビルドを確認する
2. 必要なファイルだけをVPSへ配置する
3. VPS上でDockerグループIDを確認する
4. VPS上で `.env.production` を作成する
5. `.env.production` の読み取り権限を所有者だけに制限する
6. PostgreSQLとRedisを起動する
7. FastAPIを起動し、内部の `/health` を確認する
8. Caddyを起動し、HTTPS証明書を取得する
9. 公開URLの `/health` とReact画面を確認する
10. Workerを起動し、安全なテスト対象で診断を確認する
11. MyDNSへのIP通知を毎日自動実行する

## 秘密値の扱い

- `.env.production` はVPS内だけに置く
- `.env.production` をGitへ追加しない
- パスワードやHMAC秘密値をチャット、スクリーンショット、ログへ表示しない
- SSH秘密鍵をVPSやリポジトリへコピーしない
- HMAC秘密値は、連携するNAGeCen本体側にも安全な方法で設定する

VPS上では、最終的に次の権限へ設定します。

```bash
chmod 600 .env.production
```

## 確認コマンド

本番設定の読み取り確認:

```bash
docker compose \
  -f compose.production.yaml \
  --env-file .env.production \
  config --quiet
```

コンテナの状態確認:

```bash
docker compose \
  -f compose.production.yaml \
  --env-file .env.production \
  ps
```

公開後のDB接続確認:

```bash
curl https://nagecen-security.ucu4-lab.mydns.jp/health
```

正常時は、次の応答になります。

```json
{"status":"ok","database":"connected"}
```

## 更新時の注意

### 2026-10-06 提出用の配信

- `frontend` で `npm run build:demo` を実行し、`dist-demo/` の内容をVPSの `/opt/nagecen-security/submission-public/` へ配置します。
- `compose.production.yaml` に `compose.submission.yaml` を重ね、webだけを `up -d --no-deps --no-build web` で切り替えます。
- `Caddyfile.submission` は `/api/*` を503にし、実診断・認証連携を公開側から停止します。`/health` は維持します。
- Workerを停止し、既存コンテナのrestart policyも `no` に変更しています。DB・バックエンド・共有鍵は変更していません。
- 提出用トップはログインせず既存の一時停止モーダルを表示します。プレビューは実通信を行いません。
- 以前の公開ファイルと配信設定はVPSの `/opt/nagecen-security/backups/submission-20261006/` に保存しています。
- 通常運用へ戻す場合は別途確認のうえ、overrideなしでwebを再作成します。WorkerやAPIは利用条件の確認前に再開しないでください。

### 通常更新

- ローカル開発では引き続き `docker compose up` を使用する
- 本番操作では必ず `-f compose.production.yaml` を付ける
- データベースのDockerボリュームを削除しない
- 本番更新前に、変更内容とデータベース移行の有無を確認する
- 手作業で開発用・アップロード用のコードコピーを二重管理しない
