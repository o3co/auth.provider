# Recipe: a login page with a second factor

The module cards are the source of truth. Where this page and a card disagree, the card wins. This page orders the steps and points to the cards; every request and answer below is recorded from a running app, on each pull request, so it does not go stale.

It continues the [login page guide](login-page.md): a password login, then a one-time password from an authenticator app (TOTP) as the second factor. Users come from your user ledger over HTTP, and state is kept in Redis.

## Generate the app

<!-- generated:command -->
```sh
npx @o3co/create-auth-provider my-provider --pattern simple-web --axis @mod/store=@mod/redis --axis @mod/users=@mod/users-http --second-factor @mod/mfa,@mod/mfa-flows,@mod/mfa-totp
```
<!-- end generated -->

Set what the generated README asks for, among them:

- Leave `mfa.mode` at its default, `required`, so every login asks for a second factor (the `mfa` card).
- The seal key, which seals each user's TOTP secret (the `seal` card).
- Your ledger's `users-http.verify-url` and `users-http.credential` (the `users-http` card), and its host in `outbound.allow` (the `outbound` card). Do not set `users.registered`: users come from the ledger, and boot is refused where both are set.
- The Redis URL (the `redis` card). For a single local Redis server, set `redis.replication = none`, since the example's `replicas` requires replicas, and run the server with `appendonly yes` and `appendfsync always` ([runbook: Redis](runbook.md#redis)).

Every key is in the [configuration reference](configuration.md). The second factor's routes are in the [route reference](routes.md), and the cards of `mfa-flows` and its internal modules say what each answers (the two enrollment routes, the `mfa-enrollment` card).

## 1. A first login asks the user to bind a factor

The page logs in as the login page guide shows. For a user with no second factor yet, the login is held: the answer names a transaction, to carry to the next request in the body.

<!-- generated:first-login -->
```http
GET /oauth/authorize?response_type=code&client_id=my-web-app&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid&state=xyz&code_challenge=7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM&code_challenge_method=S256
```

```http
302
location: https://auth.example/login?redirect_to=https%3A%2F%2Fauth.example%2Foauth%2Fauthorize%3Fresponse_type%3Dcode%26client_id%3Dmy-web-app%26redirect_uri%3Dhttps%253A%252F%252Fapp.example%252Fcallback%26scope%3Dopenid%26state%3Dxyz%26code_challenge%3D7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM%26code_challenge_method%3DS256
```

```http
GET /session/csrf
```

```http
200
content-type: application/json

{
  "csrf_token": "<csrf_token>",
  "header_name": "x-csrf-token",
  "body_field": "csrf_token",
  "expires_in": "<seconds>"
}
```

```http
POST /session/login
content-type: application/json
x-csrf-token: <csrf_token>

{
  "username": "alice",
  "password": "<password>",
  "redirect_to": "https://auth.example/oauth/authorize?response_type=code&client_id=my-web-app&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid&state=xyz&code_challenge=7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM&code_challenge_method=S256"
}
```

```http
403
content-type: application/json

{
  "error": "mfa_enrollment_required",
  "transaction": "<transaction>",
  "expires_in": "<seconds>"
}
```
<!-- end generated -->

## 2. Bind TOTP

The page starts the binding with the transaction, shows the secret to the user's authenticator app (the `otpauth_uri` makes a QR code), and completes it with the app's current code.

<!-- generated:enroll -->
```http
POST /session/mfa/enrollment
content-type: application/json
x-csrf-token: <csrf_token>

{
  "kind": "totp",
  "transaction_id": "<transaction>"
}
```

```http
200
content-type: application/json

{
  "secret": "<secret>",
  "otpauth_uri": "otpauth://totp/auth.example%3Au-alice?secret=<secret>&issuer=auth.example&algorithm=SHA1&digits=6&period=30",
  "algorithm": "SHA1",
  "digits": 6,
  "period": 30,
  "transaction": "<transaction>",
  "expires_in": "<seconds>"
}
```

```http
POST /session/mfa/enrollment/complete
content-type: application/json
x-csrf-token: <csrf_token>

{
  "transaction_id": "<transaction>",
  "proof": "<totp_code>"
}
```

```http
200
content-type: application/json

{
  "factor": {
    "id": "<factor_id>",
    "kind": "totp"
  }
}
```
<!-- end generated -->

The factor is bound, but this login opens no session: a factor bound on the password alone counts from the next sign-in (the `mfa-enrollment` card). Send the user back to log in.

## 3. The next login asks for the factor

<!-- generated:second-login -->
```http
POST /session/login
content-type: application/json
x-csrf-token: <csrf_token>

{
  "username": "alice",
  "password": "<password>",
  "redirect_to": "https://auth.example/oauth/authorize?response_type=code&client_id=my-web-app&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid&state=xyz&code_challenge=7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM&code_challenge_method=S256"
}
```

```http
403
content-type: application/json

{
  "error": "mfa_required",
  "transaction": "<transaction>",
  "expires_in": "<seconds>"
}
```
<!-- end generated -->

The page reads the transaction to learn which factors the user can use, through the `mfa-transaction` header.

<!-- generated:factors -->
```http
GET /session/mfa/transaction
mfa-transaction: <transaction>
```

```http
200
content-type: application/json

{
  "purpose": "login",
  "factors": [
    {
      "id": "<factor_id>",
      "kind": "totp"
    }
  ],
  "attempts_remaining": 5,
  "expires_in": "<seconds>"
}
```
<!-- end generated -->

## 4. Verify the code

The page sends the factor's id and the app's next code. The answer opens the session and names where to go.

<!-- generated:verify -->
```http
POST /session/mfa/verify
content-type: application/json
x-csrf-token: <csrf_token>

{
  "transaction_id": "<transaction>",
  "factor_id": "<factor_id>",
  "proof": "<totp_code>"
}
```

```http
200
content-type: application/json

{
  "redirect_to": "https://auth.example/oauth/authorize?response_type=code&client_id=my-web-app&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid&state=xyz&code_challenge=7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM&code_challenge_method=S256"
}
```
<!-- end generated -->

## 5. Go on

Send the browser to the answer's `redirect_to`. The authorization endpoint now finds the session and redirects to the client with the code.

<!-- generated:continue -->
```http
GET /oauth/authorize?response_type=code&client_id=my-web-app&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid&state=xyz&code_challenge=7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM&code_challenge_method=S256
```

```http
302
location: https://app.example/callback?code=<code>&state=xyz&iss=https%3A%2F%2Fauth.example
```
<!-- end generated -->

## When the second factor's store can be lost

A user whose factors are lost from the store reads as never enrolled. To keep a record of who has enrolled at your ledger, add `@mod/mfa-witness-http`; its card says what the ledger must keep, and the [runbook](runbook.md#keeping-the-second-factor-witness-at-the-ledger) how to run it.

## A code by email

A second factor by email (`mfa-email`) mails its code. To read the codes on your machine while you develop, point `mail-smtp` at Mailpit on loopback, as [Email codes on your machine](local-mail.md) shows.
