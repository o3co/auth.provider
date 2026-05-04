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
  });

  // authenticateUrl に対して { email, password } を POST
  authenticate(username: string, password: string): Promise<User | null>;

  // authenticateByTokenUrl に対して { token } を POST
  authenticateByToken(token: string): Promise<User | null>;
}
```

- HTTP 401 または 403 の場合は `null` を返す。
- その他の非 OK ステータスの場合はエラーをスローする。

## 使い方

```typescript
import { createDefaultFactories } from "@o3co/auth-provider-core";
import { registerBuiltinAdapters } from "@o3co/auth-provider-foundation";

const { userFactory } = createDefaultFactories();

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
