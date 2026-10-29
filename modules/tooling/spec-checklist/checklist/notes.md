# Notes

The notes a `note:` mark names, each written once as `- **N-<name>** <text>`.

- **N-https** Held for a production deployment (`kernel.environment = production`, the default), which refuses a plain-http public origin and issuer at boot: there the URL is https. Outside production, a deployment that declares `http.insecure-origin = true` may serve it over plain http, for trying the provider on one machine.
- **N-least-privilege** Held for what the provider issues: a token's scope stays within what the client is allowed (`client-allowance`), and its audience is narrowed by a resource indicator (`resource-indicators`). What a resource server takes a token for is its own.
