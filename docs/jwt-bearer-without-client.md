# A JWT bearer grant that names no client

Some senders of JWT bearer assertions (RFC 7523) authenticate as no client: an agent platform or a fleet of devices sends only `grant_type`, `assertion` and, if it likes, `scope` and `resource`, with no `client_id` and no credential (RFC 7523 §3.1). The provider takes such a request for the one client the trusted issuer's entry names in `client`. It is opt-in: nothing changes until an entry of `jwt-bearer.issuers` sets `client`.

The `jwt-bearer` card and its internal card `src/issuers` hold the full contract; this page puts the configuration together.

## Compose the grant

The `a2a` pattern composes the JWT bearer grant. Another pattern takes it with `--add @mod/jwt-bearer`.

## Configure it

Register one client for the issuer, and name it in the issuer's entry. A whole example, for `config/local.conf`:

```hocon
clients.registered = [
  {
    id = "agents"
    kind = "public"
    method = "none"
    sections {
      client-allowance {
        grants = ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
        scopes = ["orders:read", "orders:write"]
        default-scopes = ["orders:read"]
        audiences = ["https://api.example"]
      }
    }
  }
]

jwt-bearer {
  # The sender's clock skew; 60 seconds for Claude Tag.
  clock-skew = 60s
  issuers = [
    {
      issuer = "https://agents.example"
      jwks-uri = "https://agents.example/.well-known/jwks.json"
      subject = "as-is"
      # How long the sender's assertions live; no longer than the section's.
      max-assertion-lifetime = 10m
      # Whose assertions are taken: here, subjects of your organisation alone.
      conditions {
        subject-prefix = "org:acme/"
      }
      client = "agents"
    }
  ]
}

outbound.allow += "agents.example"
```

- **The client** is public with method `none`: nothing it authenticates with. It's allowed the JWT bearer grant alone, with the scopes and audiences the sender's tokens may carry. Leave out a `sender-binding` section for a sender that sends no DPoP proof. Boot is refused, at the entry's `client` and never by its value, on a client that is not registered, one with credentials, one allowed another grant, and one two entries name.
- **The entry** names the issuer and its keys: `jwks-uri` at https on the issuer's host, or `keys` written out (`kid`, `alg`, `public-key` as SPKI PEM). `conditions` says whose assertions are taken (`subject-prefix`, and `claims`, each a value or a list). A request naming no client carries no authentication, so the conditions are what narrow it: `accept-any-subject` is refused beside `client`. A `linked` entry, whose subjects are those `users` links, needs no conditions.
- **The key set's host** goes in `outbound.allow`, so the provider can fetch it.
- **On the sender's side**, give this server's issuer URL, or its token endpoint's, as the audience its assertions carry.

Each boot warns `jwt-bearer.clientless_issuer` with the entry's place, so the log shows that an entry takes requests naming no client.

## What the sender sends, and the answers

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=<the assertion>&scope=orders%3Aread
```

- A token is issued to the entry's client, with the assertion's subject.
- Whatever fails before the subject is taken is answered `400 invalid_grant` with `untrusted signer`, so the answer tells nothing of which issuers are trusted: the signature, the times or the audience, an issuer whose entry has no `client`, its conditions, or its link.
- The entry and its client are bound both ways, whether a request names the client by its `client_id` or names none. The entry's assertions are issued to that client alone, and the client takes its own entry's assertions alone. Any other is `assertion is for another client`, using up no `jti`. One `jti` is used up once, whether a request names the client or not.
- Once one entry has a `client`, a JWT bearer request carrying nothing a client authenticates with is answered `400 invalid_grant`, whatever its `iss`, instead of `401 invalid_client`.

## Related

- Each setting named here is in the [configuration reference](configuration.md): `jwt-bearer.*` and a client's `client-allowance` section.
- What changed in 0.19 for this grant is in the [migration guide](migration.md#from-018-to-019).
- The risk of an issuer taking requests that name no client is in the [security model](security-model.md).
