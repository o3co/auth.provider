# @o3co/auth-provider-foundation

auth.provider 向けの本番用 HTTP ユーザー認証アダプターパッケージ。`"http"` アダプター型を `UserRepository` ファクトリーに登録し、`authenticate` / `authenticateByToken` を上流 HTTP サービスへ委譲する。

このパッケージのスコープは v0.5.0 モジュールシステムにおける **本番用の非データベース / 外部サービスアダプター** であり、v0.5.0 時点では `HttpUserRepository` のみを提供する。以前同梱されていた Redis `CodeRepository` アダプターは Phase 10 で [`@o3co/auth-provider-redis`](../redis/README.ja.md) に移管された。

## インストール

```sh
npm install @o3co/auth-provider-foundation
# peer dependency（必須）:
npm install @o3co/auth-provider-core
```

## パブリック API

### `registerBuiltinAdapters`

`"http"` アダプター型を、指定された `userFactory` に登録する。

```typescript
function registerBuiltinAdapters(factories: {
  userFactory: AdapterFactory<UserRepository>;
}): void;
```

Redis を使った認可コードストレージが必要な場合は、`@o3co/auth-provider-redis` の builder を直接登録する:

```typescript
import { redisCodeRepositoryBuilder } from "@o3co/auth-provider-redis";
codeFactory.register("redis", redisCodeRepositoryBuilder);
```

### `HttpUserRepository`

上流の HTTP サービスに認証処理を委譲する `UserRepository` 実装。

```typescript
class HttpUserRepository implements UserRepository {
  constructor(options: {
    authenticateUrl: string;        // ユーザー名・パスワード認証用の POST エンドポイント
    authenticateByTokenUrl: string; // トークン認証用の POST エンドポイント
    timeout: number;                // リクエストタイムアウト（ミリ秒）
    maxResponseBytes?: number;      // レスポンスボディの上限、デフォルト 1 MiB
  });

  // authenticateUrl に対して { email, password } を POST
  authenticate(username: string, password: string): Promise<User | null>;

  // authenticateByTokenUrl に対して { token } を POST
  authenticateByToken(token: string): Promise<User | null>;
}
```

- HTTP 401 または 403 の場合は `null` を返す。
- その他の非 OK ステータスの場合はエラーをスローする。
- 上流が 2xx で `User`（`{ id: string, username: string, … }`）以外の JSON を返した場合もスローする — 「ユーザーが見つからない」ではなく「上流が壊れている」ケースのため。

### コンストラクタでの検証

すべてのオプションは**コンストラクタ**で検証される。設定を誤ったデプロイは最初のログイン時ではなく起動時に失敗する。

**両方の URL は `https://` でなければならない。** これらは平文のユーザー資格情報（`authenticateUrl` にはパスワード、`authenticateByTokenUrl` にはトークン）を運ぶため、`http://` は接続を弱めるだけでなく、経路上のすべてのホップに資格情報を公開する。

**唯一の例外は loopback。** ホストが `localhost`、`127.0.0.0/8` 内のアドレス、`[::1]` のいずれかであれば `http://` を許可する。この通信はマシンの外に出ないため、ローカル開発およびインプロセスのテストフィクスチャは証明書を必要としない。それ以外のホストは**プライベートレンジのアドレスやコンテナネットワークのサービス名を含めて** `https://` が必須（`http://10.0.0.5/…`、`http://user-service/…` は拒否される）。これらはデプロイが端から端まで制御していないネットワークを越えるものであり、「内部」は「暗号化済み」の同義語ではない。URL に資格情報を埋め込んだもの（`https://user:pass@…`）も拒否する。

これは [`@o3co/auth-provider-core`](../core/README.ja.md) の `oauth.jwt.issuer` と同じルールで、例外の範囲を `127.0.0.1` 単一アドレスから `127.0.0.0/8` ブロック全体へ広げ、クエリ文字列を許可している（issuer は持てないが、POST エンドポイントは正当に持ちうる）。

**`timeout` は `2147483647` ミリ秒以下の正の整数でなければならない。** `0`・負数・`NaN` は `setTimeout` ではいずれも「即時発火」に丸められ（＝すべてのリクエストが中断される）、Node のタイマー範囲を超える値は 1ms に丸められるため、「長めに待つ」つもりの設定が最短のタイムアウトになってしまう。デッドラインは**ボディ読み取りを含む**やり取り全体に適用される。ボディ読み取りは abort signal 頼みではなくデッドラインとの race で打ち切る — 実行中の `read()` は abort では確実に中断されないため。これはヘッダだけ即座に返してボディを止める slow-loris の形であり、race がなければ永久にハングする。超過したリクエストはエンドポイント名を含む `timed out after <n>ms` エラーで reject される。

**`maxResponseBytes` は正の整数でなければならない。** デフォルトは `DEFAULT_MAX_RESPONSE_BYTES`（1 MiB）。上限は `Content-Length` に対してもストリーム読み取り中にも適用されるため、ヘッダを省略する（あるいは偽る）上流も途中で打ち切られ、メモリを食い潰すことはできない。

## 使い方

```typescript
import { createRepositoryFactories } from "@o3co/auth-provider-core";
import { registerBuiltinAdapters } from "@o3co/auth-provider-foundation";

const { userFactory } = createRepositoryFactories();

registerBuiltinAdapters({ userFactory });

// ファクトリー経由で HTTP ユーザーリポジトリを生成
const userRepo = await userFactory.create({
  type: "http",
  authenticateUrl: "https://users.example.com/authenticate",
  authenticateByTokenUrl: "https://users.example.com/authenticate-by-token",
  timeout: 5000,
});
```

## 関連

- [`@o3co/auth-provider-core`](../core/README.ja.md) — コアインターフェース（`UserRepository`、`CodeRepository`、`AdapterFactory`、`createAdapterFactory`、`BuilderContext`、`PathResolver`）
- [`@o3co/auth-provider-redis`](../redis/README.ja.md) — Redis バックエンドのアダプター群（challenges、replay-seen-set、refresh-token-family、user-sessions、federation-tokens、**code-repository**、rate-limiter）
- [auth.provider](../../README.md) — リポジトリ全体のドキュメント
