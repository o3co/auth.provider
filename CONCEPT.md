# Concept

auth-provider is a self-hosted OAuth 2.0 authorization server and OpenID Connect provider for Node.js.
You generate an application with the features your deployment needs, then run it yourself.
The [README](README.md) explains how to start.

This document explains why 0.18 is built this way, for developers choosing a provider and contributors changing one.

## Identity can belong somewhere else

An authentication server does not always own the identity it authenticates.
Your system may already have a ledger that names subjects and controls their device keys.
The provider needs to use those decisions without becoming another identity database.

[provin's auth stack](https://github.com/provin-line/auth) is a concrete example.
It composes auth-provider with auth.policy-verifier for the provin wire profile of dPLaaX.
Its own scaffold generators write a composition root of each service for each deployment.

The stack adds DID authentication through `@provin-line/auth-provider-did`.
It uses the grant type `https://dplaax.dev/oauth/grant-type/did` and a `did:dplaax` resolver.
Today that package depends on the earlier `@o3co/auth-provider-core` 0.15 line, not on 0.18.

The 0.18 design follows from what such a stack needs.
An outside package must be able to add a grant without forking the provider.
Each deployment must be able to select its own modules.
Identity and device keys must be able to stay in an outside ledger.

## The ledger boundary

`users-http` asks an operator's HTTP ledger to verify passwords and look up subjects.
It translates each response into the contract owned by `users`.
When configured to resolve upstream identities, the ledger's answer is authoritative.

`signer-keys-http` asks the ledger for a signer's public keys on every JWT bearer assertion.
It keeps no answer between assertions.
A withdrawn key therefore cannot authorize another assertion through a cached positive answer.

`jwt-bearer` can require an assertion's `sub` to be the signing key's thumbprint.
With `subject = linked`, it resolves the verified signer to the subject it represents.
This lets a device key authenticate for a ledger subject without making that key the identity.

Subject revocation travels from the ledger to the provider.
`subject-revocation-http` accepts authenticated notifications and records a revocation boundary.
The modules that own sessions and tokens apply that boundary through their contracts.
Revocation cannot stop a request already past its checks.
A JWT checked independently by a resource server may remain usable until it expires.

`mfa-witness` defines a separate contract for remembering that a subject enrolled a second factor.
An implementation, such as a ledger adapter, keeps that fact apart from the factor store.
Losing the factor store must not make an enrolled subject appear never enrolled.
The contract requires durable writes and reads that do not return stale enrollment state.
An implementation that cannot answer must report unavailability.

The provider still holds state of its own, including sessions and replay-prevention records.
Its token-signing and sealing keys come from configuration, apart from any device keys a ledger supplies.

## Why 0.18 rewrites 0.17

Development is now largely done with AI agents, so changes arrive much faster.
Security requirements keep growing at the same time.

DPoP and mTLS bind tokens to a key or a certificate.
Token exchange and the device flow add paths to issuance; passkeys and federation change the evidence for a login.
Ledger revocation must still reach the sessions and tokens all those paths produce.

In 0.17, changes often reached across a shared core where feature contracts and settings accumulated.
Adding a requirement meant finding every affected place and keeping them consistent.
That reliance on attention became harder to sustain as development sped up.

0.18 makes the owner of a change explicit.
The aim is for an ordinary change to stay inside one module.
A human or agent reads its implementation and card, plus the cards it depends on.
A shared contract change still needs coordinated work across its callers.

Machines enforce the structural rules they can check; review judges whether the boundaries make sense.

## A module is a responsibility

Each module has a README called its card.
The card states what the module owns and what belongs elsewhere.
It defines the public contract and the invariants other modules may rely on.
It also names dependencies and fixes the meaning of local vocabulary.

The [owner map](modules/README.md) tells contributors where a concern belongs.
Consumers use the owner's contract instead of reaching into its implementation.
Extension points belong to the module that understands their purpose.
Dependencies follow a declared direction, and cycles are refused.

Words keep one meaning inside a module.
When another system uses different words, the boundary translates them.
An HTTP ledger response becomes a `users` answer there, and the rest of the provider never sees the ledger's format.

Cards describe the current contract only; plans and unfinished moves belong outside them.

## Complexity stays with its owner

A grant owns the checks specific to that grant.
The token endpoint authenticates the client and runs the checks around dispatching to it.
The grant contract defines what a handler receives and how its result is returned.
An outside grant uses that same extension point.

The [kernel](modules/foundation/kernel/README.md) assembles modules without knowing the names of their features.
Adding a grant type does not require teaching the kernel about it.
Additions to the kernel itself go through a human gate.

State is separated the same way: a feature declares the storage guarantees it needs.
A wiring module connects its interface to a storage implementation.

`tokens` knows nothing about sessions.
The `session-tokens` bridge records access tokens issued from a session.
When that session is explicitly closed, the bridge revokes its recorded tokens.
Session expiry is different: those tokens live out their own lifetimes.

## Refuse mistakes mechanically

The [guard](modules/tooling/guard/README.md) reads the workspace during `pnpm check` and in CI.
It rejects dependency cycles and dependencies that point against the declared order.
It checks declared runtime imports and limits public interfaces.
It also enforces budgets for module size and the cards a contributor must read.

Individual card-item size is measured and reported, but not yet refused.

Outbound HTTP goes through `outbound`, and other network use must match the package's declaration.
The guard checks this rather than relying on reviewers to spot every call.

There is no exception list to extend when a rule becomes inconvenient.
A module can gain internal modules with their own cards to keep reading scope manageable.
A public split should follow a real responsibility boundary.

The kernel checks the application being assembled.
Missing providers, conflicting contributions, invalid configuration and, in a multi-instance deployment, unsafe modules refuse boot.
Refusals are collected by assembly stage and reported by key path, without values.
The application serves nothing while boot is refused.

The guard checks repository structure; the kernel checks the chosen application.
Neither can decide whether a contract assigns responsibility well.

## Generate the deployment

`create-auth-provider` turns a pattern and feature choices into an application.
A pattern is a starting selection, such as a password-based web app or service-to-service provider.
Composition tooling adds the dependencies the selection needs.
It also adds declared storage wiring and bridges between selected features.

The generated project belongs to you: a module list, its configuration and a Dockerfile.
Adapters let deployments choose an implementation, such as Redis in place of in-memory storage.

An outside module can implement a contract or contribute through an extension point.
You add it to the generated application's module list; no fork is needed.
Replacement implementations can run the contract tests published by the owner.

## Keep behavior separate from implementation

Conformance scenes describe behavior through HTTP and boot refusals.
They do not depend on module internals, so boundaries can move while behavior stays tested.

CI runs the scenes against 0.18 and the 0.17.0 baseline.
It also runs applicable scenes against each pattern's generated application.
Legacy setup limitations and agreed behavior differences are declared explicitly.

Release checks generate each pattern from packed packages, then type-check and boot it.
This checks what a deployment receives, as well as the modules in the workspace.

## Security crosses module boundaries

Some promises cannot be checked inside one module.
Closing a session must revoke the access tokens recorded for it.
An unavailable storage answer must not become “absent” or permission to proceed.
A one-time credential must remain spent across instances.
Outbound HTTP must pass through the destination policy.

The maintainers' release practice is to run the full test suite for every release.
They also check the whole product against its cross-cutting security promises.
Before building a design that changes the system's shape, two independent reviewers examine it adversarially.

These are development practices, not guarantees of correctness.
The [security model](docs/security-model.md) states the guarantees and the conditions a deployment must meet for them to hold.

## What you take on

You operate this software and the outside services your selection needs.
Small deployments list users in configuration; others keep identity records in their own ledger.

An integrated identity server may suit a team that wants account management included.
This provider has no admin console, and you supply login and consent pages.
Sign-up and account recovery belong to the surrounding application.

Authorization decisions belong in your services or a policy engine such as auth.policy-verifier.
Enforcement belongs at service boundaries: auth.proxy can validate tokens in front of services.
protobuf.interceptors connects service authorization to gRPC and ConnectRPC.

The module structure has a cost: more packages and contracts to navigate than in a monolith.
Extension authors must meet the invariants of the card they build on.
Operators must understand their selected composition and its storage requirements.

0.18 is still a prerelease, and a new release candidate may break compatibility.
Moving from 0.17 requires new package names and rewritten configuration.
Stored state is not migrated.
Read the [migration guide](docs/migration.md) before planning that move.

## Read next

- [README](README.md) for installation and deployment choices.
- [Owner map](modules/README.md) to find the contract behind a concern.
- [Security model](docs/security-model.md) for guarantees and operator responsibilities.
- [CONTRIBUTING.md](CONTRIBUTING.md) for the checks and rules a change must follow.
