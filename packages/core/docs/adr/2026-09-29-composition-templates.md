# ADR 2026-09-29 — Composition templates: one per composition shape

## Status

Accepted (2026-09-29). `create-app` scaffolds from a named template
(`--template <name>`, `standalone` by default) and ships every template the
repository holds; CI builds, tests and images every one of them against the
packed tarballs. The second template, `m2m`, is designed here and lands
after [#728](https://github.com/o3co/auth.provider/issues/728) and
[#752](https://github.com/o3co/auth.provider/issues/752) (a
composition with no authorization-code grant still carries a browser
surface); [#751](https://github.com/o3co/auth.provider/issues/751)
tracks the steps.

- Written against: `develop` at `bb180ae5f`. Every "today" below was checked
  there, and the umbrella repository (o3co/auth) at its `develop`.

## Context

The repository has one composition root, `templates/standalone`. It depends on
eight of the sixteen workspace packages (core, oauth, session, redis,
foundation, federation-google, federation-oidc, federation-grants) and chooses
among what they provide with configuration switches: the federations,
federation grants, the session and code stores, the rate limiter, the consent
store. It is what `create-app` copies, and the only composition CI tests the
way a scaffold is used — against the packed tarballs, in its image, and under
the umbrella E2E.

Two things follow from there being one.

**Only one shape of deployment is ever booted.** `tools/composition` boots the
standalone's composition with every other package added to it. In a
composition that large, a slot one module requires is often filled by a module
that happens to be there, so a dependency nobody declared stays invisible
until a deployment leaves that neighbour out. And a combination nobody boots
is not known to boot: the standalone's own Redis branch shipped unable to
(`missing-required-component` for two client slots; CHANGELOG, "The
scaffold's Redis branch boots again"), because its suite checked which modules
the branch selects and not whether the selection could be satisfied. The
packages' READMEs make claims about smaller compositions — the oauth README
says login and the browser session are a package of their own "because an
API-only deployment issues tokens without them" — that no composition in the
repository exercises. Checked against the code, that one does not hold today:
`oauthModule` requires a code repository and a login URL, mounts `/authorize`
and `/userinfo` unconditionally, and discovery requires the OpenID Connect
fields (`packages/oauth/src/module.mts`, `packages/oauth/src/routes.mts`,
`packages/core/src/discovery/buildDocument.mts`).

**A template is the worked answer to "how do I wire this".** Where a feature
needs several modules, stores and settings together — MFA is the next one
(the MFA ADR's step 20) — the composition root that wires it is the example an
operator copies. One composition root has to be every example at once, behind
switches.

How other authorization servers split their starting points:

- Hosted identity providers split by **client type** — Auth0's Regular Web,
  Single-Page, Native and Machine-to-Machine applications
  ([Auth0](https://auth0.com/docs/get-started/applications)), Zitadel's Web,
  User Agent, Native and API
  ([Zitadel](https://zitadel.com/docs/guides/manage/console/applications)). Each
  type is a preset of allowed grants and client authentication methods on
  **one** server, not a different server.
- Libraries split their templates by **UI or headless** and by **storage**:
  Duende IdentityServer ships `duende-is-empty` (no UI), `duende-is-ui`,
  `duende-is-inmem` ("In-Memory Stores and Test Users"), `duende-is-ef`,
  `duende-is-aspid` and the full `duende-is`
  ([Duende](https://docs.duendesoftware.com/identityserver/overview/packaging/)).
  None splits by grant: device authorization, consent and external login sit
  together in the full template. Per-flow material goes into samples
  ([OpenIddict samples](https://github.com/openiddict/openiddict-samples)), and
  node-oidc-provider keeps one example whose features are configuration flags
  ([node-oidc-provider](https://github.com/panva/node-oidc-provider/tree/main/example)).
- What goes wrong: one starting point per feature combination multiplies, and
  starting points for deprecated flows (the resource owner password grant)
  outlive the advice against them.

## Decision

### D1. A template per composition shape

A template exists for each **composition shape**: what the deployment exposes
and to whom. The shape changes the package set, what is mounted and what
cannot be expressed by configuration. Today there are two:

- **Browser-facing**: a browser session and the login, logout and
  authorization pages' back end.
- **Headless**: tokens for machines, with no browser session, no cookie and no
  `/authorize`.

What is **not** a template:

| Varies | Where it lives |
| --- | --- |
| A feature or grant (device grant, MFA, passkeys, consent, a federation, DPoP, mTLS, JWT bearer, token exchange) | A switch in each template whose shape it belongs to, once that template installs its package (the standalone installs none of the device grant, WebAuthn, DPoP, mTLS and token exchange today) |
| Scale and storage (one replica or several, memory or Redis) | Configuration: `deployment.mode` and the adapter selection |
| The kind of client (web, single-page through a back end, native) | The client registration |

A switch is held to the same rule as a template: every branch of it is booted
by the template's own suite (the MFA ADR's step 20 tests MFA on and off).

### D2. The templates

- **`standalone`** — the browser-facing identity provider. It keeps its name:
  the umbrella E2E builds it by path (`tests/dockerfiles/provider.Dockerfile`
  and `tests/docker-compose.yml` in o3co/auth), and the documentation and
  `create-app`'s default name it.
- **`m2m`** — the headless token service: `client_credentials` with client
  secrets and `private_key_jwt`, RFC 7523 JWT bearer, RFC 8693 token exchange,
  DPoP and mTLS behind switches, introspection, revocation and the JWKS. It has
  no session package, no `express-session`, no login URL and no code store.
  JWT bearer resolves each assertion's subject to a user, so with it switched
  on `m2m` also needs the user service (`foundation`'s HTTP user repository),
  as `standalone` does. Its suite asserts the absence as well as the presence:
  `/oauth/authorize` and `/session/*` answer `404`, and no response sets a
  cookie.

JWT bearer is a switch of both shapes (D1). A browser-facing deployment uses
it too: auth.proxy's injection mode exchanges an external credential for a
token with it, at the same provider that serves its session grant, and the
umbrella E2E leaves that exchange out today because `standalone` wires no
assertion verifier. The module that builds the verifier over a static issuer
registry from the configuration is written once and shared by the templates
(D4).

Two templates asked for by their use — "a simple web deployment", "an admin
API" — are the same two shapes: the first is `standalone` on one replica with
in-memory stores; the second is `m2m` when its callers are machines, and
`standalone` with MFA required and passkeys when they are people.

### D3. What a template is, and what holds every template to account

A template is a directory under `templates/` — not a symbolic link, not
dot-named — holding a `package.json`, and named in lowercase kebab-case (the
name is a CLI argument and, in CI, a Docker image tag). The rule is written
once, in `create-app/scripts/templates.mjs`; the build refuses a template that
breaks the naming rule, and a `templates/` holding none.

- `create-app` ships every template (`scripts/copy-templates.mjs`) and
  scaffolds the one named by `--template`, `standalone` by default. A name is
  looked up in the list of shipped templates, never resolved as a path.
  `published-package.test.mts` packs the package and requires the tarball to
  carry exactly the repository's templates, each of which must scaffold from
  it.
- CI's publish-readiness job reads the list from the same module, builds and
  tests every template against the packed tarballs, and builds each one's base
  image and installs its dependency set on it.
- Dependabot watches `templates/*` and bumps a base image in one pull request
  across every template (`group-by: dependency-name`). Grouping applies to
  version updates only: a security update arrives as one pull request per
  template, and the drift test of D4 fails each until the same bump is applied
  to the other templates in it.

### D4. Files the templates share are copied, and held identical

A template is copied into a project and owned by its operator from then on, so
it cannot import its host process from a package without the operator losing
the ability to read it. The files that are not a choice of the template are
therefore copied into each template, and a drift test that lands with the
second template requires them to be byte-identical. The candidates are the
host process (`listen`, `logger`, `metrics`, `routes`, `shutdown`), the
`Dockerfile`, `.dockerignore`, `.gitignore`, `tsconfig.json`, the vitest
configuration, and the JWT-bearer verifier module (D2). A candidate that reads
a template's own settings is made neutral before it is shared: `shutdown.mts`
sizes its drain from `federationGrants` (`cleanupAllowanceFor`), which the
browser-facing composition hands it instead — as #728 also asks, since a
composition root reads no package's key.

Rejected:

- **A shared runtime package.** It would deliver a fix without a re-scaffold,
  but #290 moved graceful shutdown out of a package and into the scaffold so
  that "does SIGTERM wait for in-flight requests, and for how long?" is
  answered by the code an operator deploys. Moving the host process into a
  package reverses that.
- **A base template with per-template overlays, assembled by `create-app`.**
  A template would no longer be a project that builds and tests where it
  stands, and CI would test an assembly rather than what is in the repository.

### D5. The repository's own guards read every template

The drift tests in core that walk `templates/standalone/src` by name
(`errorText`, `designVocabulary`, `mfaEnrollmentWitness`,
`sessionAdmissionCallers`, `auditEventInventory`) walk
every `templates/*/src` when the second template lands, each first shown to
miss it; `reference-env-names` reads every template's `config/`, not only
`templates/standalone/config`. The guards that list workspaces explicitly
(`logErrorProjection`'s source roots, `packageImports`'s compositions) name
it.

### D6. Relation to the MFA ADR

MFA is a switch of the browser-facing shape (D1). Step 20 wires it into
`standalone`, and `create-app --no-mfa` applies to a template that has a
browser session; `m2m` has no login for a second factor to interrupt.

## Not now

- **A FAPI 2.0 profile.** It is a clear, testable shape of its own — pushed
  authorization requests required, sender-constrained tokens, `private_key_jwt`
  or mTLS client authentication — but pushed authorization requests (RFC 9126)
  are not implemented. Revisited when they are.
- **A leaner browser-facing template** (without federation grants, say): the
  same shape as `standalone`, so a switch, not a template.
- **Client presets** for web, single-page-through-a-back-end and native clients
  in `standalone`'s `clients.yaml.example`: the hosted providers' split, which
  belongs in the client registry (D1).

## The adapter section (#728's B5)

#728's B5, as amended on 2026-09-29
([decision](https://github.com/o3co/auth.provider/issues/728#issuecomment-5891849965)),
puts adapter selection in a top-level section the composition root owns, with
the same name in every template:

```hocon
adapters {
  rateLimiter = "redis"   # ADAPTERS_RATE_LIMITER
}
```

Environment variable names follow the path (B9), so a setting has one
variable in every template that has it, and the runbook and `.env.example`
need one table. Once #728 lands, each template's composition root reads this
section alone, with its own schema, before it chooses modules; until then the
templates read the selection keys in core's schema, as `standalone` does
today. `adapters` is a reserved section name: no module may be named
`adapters` (`moduleNames.drift` can hold that), and B8's notice of sections
no module owns leaves it out.

Rejected:

- **A section named after the template** (`standalone { adapters { … } }`, B5
  as first decided): it gives the same setting a different variable in each
  template (`STANDALONE_ADAPTERS_*`, `M2M_ADAPTERS_*`).
- **A shared wrapper** (`composition { adapters { … } }`, proposed on #728):
  under B7 a module's `enabled` is its own key, so the composition root owns
  nothing but adapter selection and needs no namespace of its own.
