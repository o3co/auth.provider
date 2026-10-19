# auth-provider

[![CI](https://github.com/o3co/auth.provider/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/o3co/auth.provider/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@o3co/create-auth-provider/next)](https://www.npmjs.com/package/@o3co/create-auth-provider)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

[English](README.md) | 日本語

OAuth 2.0 と OpenID Connect の provider です。小さな module を、生成した app が組み立てて作ります。配備に要る module を選ぶと、各 module が自分の route、設定、store を持ち込み、要るものが欠けていれば起動を拒みます。

0.18 は、0.17 を新しい package 名で作り直したものです。0.17 の配備を移すときは、先に[移行の手引き](docs/migration.md)を読んでください。

## 何をして、何を他に任せるか

provider は署名の鍵と session の状態を持ちます。そのため relying party が token を作れる鍵を持つことはなく、アクセスを決める層と強制する層は、それぞれ独立に変えられます。

すること:

- **利用者のログインと session の維持**: 利用者の台帳で確かめるパスワード、上流の identity provider (OpenID Connect、Google、GitHub、Apple)、passkey によるログイン。組み込めば第 2 要素 (認証アプリ、メールのコード、リカバリーコード、セキュリティキー) も使えます。logout で session を終えます。relying party から始まる logout も含みます。
- **client の認証**: secret、署名した assertion、PKCE を使う public client、client ID metadata document。
- **token の発行と管理**: authorization code、refresh、client credentials、JWT bearer、device authorization、token exchange の各 grant。ID token と userinfo。同意。introspection と revocation。鍵 (DPoP) や証明書 (mTLS) に結び付けた token。
- **公開**: 署名の鍵と discovery document。
- **保持**: 上流の provider が出す token と、それを使うために利用者が与える grant。
- **メールの送信**: メールの第 2 要素と、アカウントのアドレスの証明のため。

他に任せること:

- **決めること**: token が何を許すか。policy verifier が決めます。
- **強制すること**: その判断をサービスの中で強制すること。サービスの interceptor か、前に置く token を確かめる proxy が受け持ちます。
- **利用者の台帳**: 利用者が誰で、パスワードは何か。provider はあなたの台帳 (HTTP 越し、または設定の中の一覧) に問い合わせ、その横に要るものだけを持ちます。上流の identity との結び付きや、証明済みの連絡先などです。
- **頁**: ログインと同意の頁は配備のものです。
- **利用者の登録とアカウントの回復。**

## はじめかた

pattern の 1 つから配備を生成します。

```sh
npx @o3co/create-auth-provider@next my-provider --pattern simple-web
cd my-provider
```

続きは生成された `README.md` に従ってください。pattern が要る設定を挙げていて、project には Dockerfile が付きます。

- **pattern。** 各 pattern は配備の種類の 1 つです。パスワードでログインする `simple-web` は、外のシステムを要りません。何のための pattern かは [patterns の card](modules/scaffold/create-app/src/patterns/README.md) と各 pattern の card にあります。知らない名前は拒まれ、使える名前が示されます。`--add` で pattern に機能を足せます。ほかの option は `--help` で分かります。
- **自分で選ぶ。** pattern の代わりに module を挙げると、app はそれを組み立て、要る wiring と bridge を足します。

何が生成されるかは [create-app の card](modules/scaffold/create-app/README.md) にあります。

## 作り

- **module。** 関心ごとに 1 つの module が `modules/<group>/<name>` にあります。その README (module の card) が契約です。何をするか、何を提供するか、何を約束するか、何に依存するかを書いています。
- **owner map。** 契約、設定、拡張点、語のそれぞれをどの module が持つかは [modules/README.md](modules/README.md) にあります。探す前にここを引いてください。
- **kernel。** module は [kernel](modules/foundation/kernel/README.md) を通して契約と拡張点を宣言し、ほかの module に contribution を出します。kernel は module を起動し、設定の section を読み、問題があればすべてを一度に挙げて起動を拒みます。
- **組み合わせ。** 選んだものにどの wiring、adapter、bridge が付くかは [combinations](modules/scaffold/combinations/README.md) が決めます。
- **guard。** `pnpm check` は [guard](modules/tooling/guard/README.md) を回します。guard は workspace を規則に従わせます。依存の向き、各 package の公開の面、各 module とその card の大きさです。

## 拡張

自分の module も、提供される module と同じように組み立てられます。

- **契約と拡張点** は [kernel の card](modules/foundation/kernel/README.md) に書いてあります。各機能の card は、その機能が提供する拡張点を挙げています。
- **adapter と bridge** は、何の代わりになるか、何をつなぐかを manifest で宣言します。[combinations](modules/scaffold/combinations/README.md) が説明しています。
- **契約の試験。** 各 module は契約の試験を `./testing` で公開しています。自分の実装をそれで確かめられます。

## package

0.18 は関心ごとに 1 つの package `@o3co/auth-provider-<concern>` として、すべて同じ版で公開します。各 module は subpath です。自分で名前を挙げることはほとんどありません。生成した app が、組み立てるものに依存します。0.17 の package との対応は[移行の手引き](docs/migration.md#packages)にあります。

## 設定

各 module は HOCON の設定のうち自分の section を読みます。知らない key、組んでいない module の section、使えない値があれば起動を拒みます。pattern から生成した project は、スカラーの設定を環境変数から読みます。すべての key、既定値、意味は[設定の一覧](docs/configuration.md)にあります。

## 運用

- [運用の runbook](docs/runbook.md): 配備が用意するもの、Redis、鍵の入れ替え、更新、利用者の失効、probe と alert、停止。
- [セキュリティモデル](docs/security-model.md): provider が保証することと、配備に任せること。
- [audit event](docs/audit-events.md): すべての event とその属性。
- [設定の一覧](docs/configuration.md)。
- [0.17 からの移行](docs/migration.md)。
- [リリース](docs/releasing.md): maintainer 向け。

## 版

1.0 より前の release は、minor の版で互換性を壊すことがあります。壊す release にはそれぞれ移行の手引きがあります。release candidate は npm の `next` tag で公開します。

セキュリティの直しは、最新の 0.18.x にだけ出します。弱点を見つけたら[セキュリティの方針](SECURITY.md)に従って報告してください。

## 開発

```sh
pnpm install
pnpm check
```

`pnpm check` は型の確かめ、lint、試験、guard、distribution の確かめを回します。Docker が要る試験は `pnpm test:integration` で回します。

変更の作り方、確かめ方、commit の仕方は [CONTRIBUTING.md](CONTRIBUTING.md) にあります。

## 関連する project

- [auth](https://github.com/o3co/auth): 全体の repository です。構成の説明と、部品をまたぐ end-to-end の試験があります。
- [auth.policy-verifier](https://github.com/o3co/auth.policy-verifier): 認可の判断をする policy の engine です。
- [auth.proxy](https://github.com/o3co/auth.proxy): サービスの前で token を確かめる、任意の reverse proxy です。
- [protobuf.interceptors](https://github.com/o3co/protobuf.interceptors): gRPC と ConnectRPC のサービスの中の認可です。introspection をこの provider に、判断を policy verifier に頼みます。

## License

[Apache License 2.0](LICENSE)。

Copyright 2026 1o1 Co. Ltd. Licensed under the Apache License, Version 2.0.
