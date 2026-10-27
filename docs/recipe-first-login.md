# Recipe: a first login

The module cards are the source of truth. Where this page and a card disagree, the card wins. This page orders the steps and points to the cards; every command, the configuration file and every request and answer below are recorded from a running app, on each pull request, so they do not go stale.

It takes a new app from generation to its first token on your machine: a user in the configuration, a password login, and a client that uses the authorization code flow with PKCE. The app keeps its state in memory and is reached over plain http at `localhost`.

## Generate the app

<!-- generated:command -->
```sh
npx @o3co/create-auth-provider my-provider --pattern simple-web
```
<!-- end generated -->

The generated README lists every key the app reads and where each is written. This recipe writes them all in one file, `config/local.conf`.

## Make a signing key

The app signs its tokens with this key (the `keys` card). This prints a new Ed25519 key as PKCS8 PEM:

<!-- generated:signing-key -->
```sh
node -e 'console.log(require("node:crypto").generateKeyPairSync("ed25519").privateKey.export({format:"pem",type:"pkcs8"}).trim())'
```
<!-- end generated -->

## Hash a password

Users listed in the configuration keep a bcrypt or scrypt hash of their password, never the password (the `users` and `secret-hash` cards). This reads a password on standard input and prints its scrypt hash; type the password, then press Ctrl-D:

<!-- generated:password-hash -->
```sh
node -e 'const c=require("node:crypto"),s=c.randomBytes(16),p=require("node:fs").readFileSync(0,"utf8").replace(/\r?\n$/,""),k=c.scryptSync(p,s,32,{N:2**15,r:8,p:1,maxmem:2**26}),b=(x)=>x.toString("base64").replace(/=+$/,"");console.log(`$scrypt$ln=15,r=8,p=1$${b(s)}$${b(k)}`)'
```
<!-- end generated -->

## Write the configuration

Write `config/local.conf` with the key and the hash:

<!-- generated:local-conf -->
```hocon
kernel.deployment = single
kernel.environment = development
issuer.url = "http://localhost:8080"
http {
  public-origin = "http://localhost:8080"
  insecure-origin = true
}
authorize.login-page = "http://localhost:8080/login"
tokens.revocation = denylist
claims-selection.mode = on
store.accept-volatile = true
audit.receivers = [log]
keys.signing {
  kid = signing-1
  alg = EdDSA
  private-key = """-----BEGIN PRIVATE KEY-----
<the key the script printed>
-----END PRIVATE KEY-----"""
}
users.registered = [
  { identifier = alice, password-hash = "<the hash the script printed>" }
]
clients.registered = [
  {
    id = my-app
    kind = public
    method = none
    sections {
      client-allowance { grants = [authorization_code], scopes = [openid], default-scopes = [openid], audiences = [] }
      authorize { redirect-uris = ["http://localhost:3000/callback"] }
      consent { first-party = true }
    }
  }
]
```
<!-- end generated -->

- `http.insecure-origin = true` lets the public origin be plain http, for trying the app on your machine only (the `http` card). A deployment uses https.
- With no `consent.page`, no user is asked for consent, and only a first-party client is served: `my-app` is marked `first-party` (the `consent` card).
- `claims-selection.mode = on` takes the `claims` request parameter, which every deployment states; the `claims-selection` card says when it is `off` or `draining` instead.
- The login page at `authorize.login-page` is yours to serve; the [login page guide](login-page.md) says what it sends. The steps below make its requests directly.
- `my-app` is a public client: it authenticates with PKCE alone (the `clients` card). Its redirect URI is matched by exact string (the `redirect-uris` card of `authorize`).

Start the app as the generated README's Start section says, with this file as the local layer.

## 1. Log in

The client sends the browser to the authorization endpoint. With no session yet, it is sent to the login page, which takes a CSRF token and posts the user's identifier and password. The answer names where to go next: the authorization request again, which now redirects to the client with a code.

<!-- generated:login -->
```http
GET /oauth/authorize?response_type=code&client_id=my-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid&state=xyz&code_challenge=7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM&code_challenge_method=S256
```

```http
302
location: http://localhost:8080/login?redirect_to=http%3A%2F%2Flocalhost%3A8080%2Foauth%2Fauthorize%3Fresponse_type%3Dcode%26client_id%3Dmy-app%26redirect_uri%3Dhttp%253A%252F%252Flocalhost%253A3000%252Fcallback%26scope%3Dopenid%26state%3Dxyz%26code_challenge%3D7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM%26code_challenge_method%3DS256
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
  "redirect_to": "http://localhost:8080/oauth/authorize?response_type=code&client_id=my-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid&state=xyz&code_challenge=7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM&code_challenge_method=S256"
}
```

```http
200
content-type: application/json

{
  "redirect_to": "http://localhost:8080/oauth/authorize?response_type=code&client_id=my-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid&state=xyz&code_challenge=7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM&code_challenge_method=S256"
}
```

```http
GET /oauth/authorize?response_type=code&client_id=my-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid&state=xyz&code_challenge=7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM&code_challenge_method=S256
```

```http
302
location: http://localhost:3000/callback?code=<code>&state=xyz&iss=http%3A%2F%2Flocalhost%3A8080
```
<!-- end generated -->

## 2. Exchange the code for tokens

The client exchanges the code at the token endpoint, with the verifier its challenge was made from (the `code-grant` and `token-endpoint` cards).

<!-- generated:token -->
```http
POST /oauth/token
content-type: application/x-www-form-urlencoded

grant_type=authorization_code&code=<code>&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&client_id=my-app&code_verifier=vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
```

```http
200
content-type: application/json

{
  "id_token": "<id_token>",
  "access_token": "<access_token>",
  "token_type": "Bearer",
  "expires_in": "<seconds>",
  "scope": "openid"
}
```
<!-- end generated -->

Every key is in the [configuration reference](configuration.md), and every route in the [route reference](routes.md).
