# @o3co/auth-provider-foundation

auth.provider 向けの組み込みリポジトリ実装パッケージ。HTTP ベースのユーザー認証と、Redis を使った認可コードのストレージを提供する。

## インストール

```sh
npm install @o3co/auth-provider-foundation
# peer dependency（必須）:
npm install @o3co/auth-provider-core
# peer dependency（任意 — RedisCodeRepository を使う場合のみ必要）:
npm install redis
```

## パブリック API

### `registerBuiltinAdapters`

組み込みアダプターのファクトリーを、指定されたファクトリーインスタンスに登録する。

- `"http"` を `userFactory` に登録 → `HttpUserRepository` を生成
- `"redis"` を `codeFactory` に登録 → `RedisCodeRepository` を生成

```typescript
function registerBuiltinAdapters(factories: {
  userFactory: AdapterFactory<UserRepository>;
  codeFactory: AdapterFactory<CodeRepository>;
  pathResolver?: PathResolver; // 任意 — "redis" モジュールのパス解決に使用
}): void;
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

### `RedisCodeRepository`

Redis に認可コードを保存する `CodeRepository` 実装。キーは `oauth:code:<base64url-code>` 形式で保存され、TTL を設定できる。

```typescript
class RedisCodeRepository implements CodeRepository {
  constructor(redis: RedisClient, defaultExpiresIn?: number); // defaultExpiresIn のデフォルトは 600 秒

  // ファクトリーメソッド — config から Redis クライアントを生成して接続する
  static create(
    config: Record<string, unknown>,
    pathResolver?: PathResolver,
  ): Promise<RedisCodeRepository>;
  // config のキー:
  //   endpointUri      (string, 必須) — Redis 接続 URI
  //   password         (string, 任意) — Redis パスワード
  //   defaultExpiresIn (number, 任意) — TTL（秒）、デフォルト 600

  initialize(): Promise<void>;   // Redis クライアントを接続する
  createCode(params: {
    code_challenge?: string;
    code_challenge_method?: string;
    expiresIn?: number;          // このコードだけ defaultExpiresIn を上書きする
  }): Promise<Code>;
  getByCode(code: string): Promise<Code | null>;
  consumeByCode(code: string): Promise<Code | null>; // アトミックな GET + DEL
  removeByCode(code: string): Promise<void>;
}
```

## 使い方

```typescript
import { createDefaultFactories } from "@o3co/auth-provider-core";
import { registerBuiltinAdapters } from "@o3co/auth-provider-foundation";

const { userFactory, codeFactory } = createDefaultFactories();

registerBuiltinAdapters({ userFactory, codeFactory });

// ファクトリー経由で HTTP ユーザーリポジトリを生成
const userRepo = await userFactory.create({
  type: "http",
  authenticateUrl: "https://users.example.com/authenticate",
  authenticateByTokenUrl: "https://users.example.com/authenticate-by-token",
  timeout: 5000,
});

// ファクトリー経由で Redis コードリポジトリを生成
const codeRepo = await codeFactory.create({
  type: "redis",
  endpointUri: "redis://localhost:6379",
  defaultExpiresIn: 300,
});
```

## 関連

- [`@o3co/auth-provider-core`](../core/README.md) — コアインターフェース（`UserRepository`、`CodeRepository`、`AdapterFactory`、`createAdapterFactory`、`BuilderContext`、`PathResolver`）
- [auth.provider](../../README.md) — リポジトリ全体のドキュメント
