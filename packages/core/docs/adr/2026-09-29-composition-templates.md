# ADR 2026-09-29 — Composition templates: one per composition shape

## Status

Accepted (2026-09-29). `create-app` scaffolds from a named template
(`--template <name>`, `standalone` by default) and ships every template the
repository holds; CI builds, tests and images every one of them against the
packed tarballs. The second template, `m2m`, is designed here and lands
after [#728](https://github.com/o3co/auth.provider/issues/728) and the
headless-composition fixes ([#TRACKING](https://github.com/o3co/auth.provider/issues/TRACKING)).

## Context

The repository has one composition root, `templates/standalone`. It depends on
most packages and chooses among them with configuration switches: the
federations, federation grants, the session and code stores, the rate
limiter, the consent store. It is what `create-app` copies, and the only
composition CI tests the way a scaffold is used — against the packed
tarballs, in its image, and under the umbrella E2E.

Two things follow from there being one.

**No composition smaller than the whole is ever booted as a deployment.**
`tools/composition` boots the union of every package. In the union, a slot one
module requires is often filled by a module that happens to be there, so a
dependency nobody declared stays invisible until a deployment leaves that
neighbour out. The standalone's Redis branch shipped unable to boot for that
reason (`missing-required-component` for two client slots, CHANGELOG, "The
scaffold's Redis branch boots again"): only the module choice was tested, not
whether the choice could be satisfied. The packages' READMEs make claims about
smaller compositions — the oauth README says login and the browser session are
a package of their own "because an API-only deployment issues tokens without
them" — that no composition in the repository exercises.
Checked against the code, that one does not hold today: `oauthModule` requires
a code repository and a login URL, mounts `/authorize` and `/userinfo`
unconditionally, and discovery requires the OpenID Connect fields
(`packages/oauth/src/module.mts`, `packages/oauth/src/routes.mts`,
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
| A feature or grant (device grant, MFA, passkeys, consent, a federation, DPoP, mTLS, token exchange) | A switch in the template whose shape it belongs to |
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
  secrets and `private_key_jwt`, RFC 7523 JWT bearer (over a static issuer
  registry the template wires from its configuration), RFC 8693 token exchange,
  DPoP and mTLS behind switches, introspection, revocation and the JWKS. It has
  no session package, no `express-session`, no login URL and no code store.
  Its suite asserts the absence as well as the presence: `/oauth/authorize`,
  `/oauth/userinfo` and `/session/*` answer `404`, and no response sets a
  cookie.

Two templates asked for by their use — "a simple web deployment", "an admin
API" — are the same two shapes: the first is `standalone` on one replica with
in-memory stores; the second is `m2m` when its callers are machines, and
`standalone` with MFA required and passkeys when they are people.

### D3. What a template is, and what holds every template to account

A template is a directory under `templates/` with a `package.json`.

- `create-app` ships every template (`scripts/copy-templates.mjs`) and
  scaffolds the one named by `--template`, `standalone` by default. A name is
  looked up in the list of shipped templates, never resolved as a path.
  `published-package.test.mts` packs the package and requires the tarball to
  carry exactly the repository's templates, each of which must scaffold from
  it.
- CI's publish-readiness job builds and tests every template against the
  packed tarballs, and builds each one's base image and installs its
  dependency set on it.
- Dependabot watches `templates/*` and bumps a base image in one pull request
  across every template (`group-by: dependency-name`).

### D4. Files the templates share are copied, and held identical

A template is copied into a project and owned by its operator from then on, so
it cannot import its host process from a package without the operator losing
the ability to read it. The files that are not a choice of the template — the
host process (`listen`, `logger`, `metrics`, `routes`, `shutdown`), the
`Dockerfile`, `.dockerignore`, `.gitignore`, `tsconfig.json` and the vitest
configuration — are therefore copied into each template, and a drift test that
lands with the second template requires them to be byte-identical.

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
`auditEventInventory`, `campaignVocabulary`) walk every `templates/*/src` when
the second template lands, each first shown to miss it. The guards that list
workspaces explicitly (`logErrorProjection`'s source roots, `packageImports`'s
compositions) name it.

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

## Open

- **The composition root's own configuration section.** #728's B5 moves adapter
  selection into a section the composition root owns, decided as
  `standalone { adapters { … } }`. With a template per shape, a section named
  after the template gives each template different environment variable names
  for the same setting (B9 derives them from the path). A section every
  template shares — for example `composition { adapters { … } }` — keeps one
  name per setting across templates. Raised on #728 for the owner's decision.
