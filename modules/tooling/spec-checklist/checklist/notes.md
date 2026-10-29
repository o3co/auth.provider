# Notes

The notes a `note:` mark names, each written once as `- **N-<name>** <text>`.

- **N-https** Held for a production deployment (`kernel.environment = production`, the default), which refuses a plain-http public origin and issuer at boot: there the URL is https. Outside production, a deployment that declares `http.insecure-origin = true` may serve it over plain http, for trying the provider on one machine.
- **N-least-privilege** Held for what the provider issues: a token's scope stays within what the client is allowed (`client-allowance`), and its audience is narrowed by a resource indicator (`resource-indicators`). What a resource server takes a token for is its own.
- **N-response-types** Held where the authorization endpoint is composed (`authorize`), which publishes `code`. A deployment without it supports no response type, so the member would hold no value, and a member with no values is left out (RFC 8414 §3.2, OpenID Connect Discovery §4.2): the two MUSTs meet there, and the metadata keeps the second. v0.17.0 published `[]`, a declared difference (`response-types-without-authorization-endpoint`).
