# Design rules and decisions

This page is for anyone changing the code. It explains module boundaries and records the project owner's design decisions.

Each module's README is its card: it describes the module's contract. The owner map, the README of the folder that holds the modules, says where new code belongs. The `guard` and `guard-imports` cards describe the automated checks. Decisions below cite the relevant rules; those rules define what `guard` enforces.

## Contents

- [What a card offers](#what-a-card-offers)
- [Dividing a package](#dividing-a-package)
- [Kinds](#kinds)
- [Deepening and splitting](#deepening-and-splitting)
- [Decisions](#decisions)

## What a card offers

A card's Offers list everything its entry points export but the types an exported function's signature carries, which belong to that function; an entry point exports nothing its card leaves out. A file's export inside the package that no entry point carries, such as a `*Takes` the root `module.ts` reads, is not the package's, and its card does not list it. Remove an export that nothing outside the package uses, but only in a bundle `distribution` does not ship (one whose concern directory's `package.json` is private, as `modules/tooling`'s is). `distribution` publishes each member of a shipped bundle at `<bundle>/<member>`, so removing one of its exports is a breaking change, made only in a minor release with an upgrade notice; until then, list it.

## Dividing a package

Storage uses a single shared contract. A feature never depends on `store` or on a capability. It declares its own store interface and required guarantees. The storage implementation treats record contents as opaque. A wiring package connects the interface to a capability such as `records`. Redis is one implementation of `store`; no feature knows about it.

Do not add fields used by only one feature to a shared record. Modules contribute the client metadata, settings and discovery entries they use. `clients`, `kernel` and `discovery` provide the extension points for those contributions.

Expose decisions through the owning module's interface. For example, a caller should ask whether a client may use a grant rather than inspect the client's settings. If callers must interpret or sort the owner's data to make that decision, add a function to the owner.

## Kinds

The kind names and their dependency order come from `kinds`; `guard` checks them. The table describes each kind and the review needed to add a module of that kind.

| Kind | What it is | Adding one |
|---|---|---|
| common | Code with no workspace dependencies. | Requires human review. |
| protocol | The contract of a wire an outside system speaks with the provider: request fields, answer shapes, what each status means, paths. Types, constants, fixed schemas and the functions that build by them, with no I/O, clock, randomness or state. It has no workspace dependencies and is not product, so both a product module and a verification package can depend on it. | Requires human review. |
| foundation | A feature-independent contract. | An ordinary change. |
| capability | A reusable implementation, such as `records`, that wiring adapts to feature-owned contracts. It depends on no feature. | Requires human review to avoid duplicating the same implementation across features. Interface changes also require review because they affect every wired feature. |
| feature | Something the provider does for its users. | An ordinary change. |
| adapter | An implementation of an owner's contract over an external system, or a default replacement for an owner without a composition module (`replaces` with `default: true`). | An ordinary change. |
| wiring | Connects a capability to one feature's store interface. It contains no branching or loops. It ships with the product; numeric parameters such as capacities are settings with defaults. | An ordinary change. |
| assembly / verification | Project scaffolding and verification tools, including conformance tests and `guard`. | An ordinary change. |

## Deepening and splitting

Package boundaries follow ownership of decisions and data; packages interact through contracts. Internal modules divide the implementation, and each has its own card. You may add internal modules as needed; `guard` measures each separately.

Deepen a module by creating an internal module when it becomes too large to read or part of it takes on a different responsibility. Keep the public contract unchanged. Deepening alone does not justify a new dependency.

When deepening a package, give each internal module a builder. The builder retrieves the contracts it needs from the build context and passes them as typed arguments to a side-effect-free constructor named `*With`. Keep route and contribution declarations in the root `module.ts`; let internal builders retrieve their own contracts. This keeps the root file from depending on every contract used by the package.

Split code into a separate package when:

- Two or more external callers need the same internal component.
- An internal component needs a dependency that the rest of the package does not.
- The component's purpose is to connect dependencies: an adapter, bridge, wiring or mapping.
- The contract exceeds its size limit, and most dependents do not use one part of it. Extracting that part reduces what those dependents must read. If nearly every dependent uses the whole contract, first look for unused members rather than splitting it.

Before splitting, check that the new package's responsibility can be described in its owner's vocabulary.

Use the following ladder one step at a time, based on actual responsibilities, dependencies and callers. Deepen code that is too large to read; size alone does not justify a new package. Potential reuse is not enough either. Choose between steps 3 and 4 only once a second caller exists.

0. The code is inline.
1. An internal module with a card. Take this step when the code is too much to read at once, or when one part starts doing a different job.
2. An internal foundation shared by two or more internal modules in the same package.
3. A function on the owner's contract. An external caller needs a decision that belongs to the owner. Keep the implementation there and expose the decision, provided the dependency follows the kind rules. This is the default for external callers.
4. A separate capability or foundation package, with human review. Only when step 3 cannot accommodate shared use across packages, a separate dependency, a responsibility outside the owner's vocabulary, or the required dependency direction.
5. An adapter or separately installed package for an external system, a component deployments replace or omit, or a heavy dependency.

When no external callers remain, remove the step-3 function and return to step 2. Follow the interface-change process in `CONTRIBUTING`: add the replacement, migrate callers, then remove the old interface.

For example, `mtls`'s PKI code is at step 1. `external-jwt`, which verifies JWTs against external keys, is a foundation at step 4. Like `outbound` and `rate-limit`, it may be used directly by features; `records` may not. `session-requirements`' entry requirements illustrate step 3: bridges use the extension points exposed by their owners.

## Decisions

These are the project owner's current decisions. "Where it lives" names the cards, rules or work records that carry each one. For automated checks, the cited `guard` rule defines what is enforced.

| Decision | Why | Revisit when | Where it lives |
|---|---|---|---|
| The deployment must keep host clocks synchronized. The provider does not correct for drift between its hosts. Clock allowances for external signers and record-retention margins are separate. | If the provider adjusted for drift, a host with a wrong clock would go unnoticed. The deployment cannot control an external signer's clock. | Never | The migration guide's note on clocks; the cards of modules that have a `clock-skew` setting |
| Contract member limits are larger for kinds that other modules build on. | Shared contracts serve more modules. | Never | `guard` G7 |
| `combinations` derives the default composition from package manifests. Wirings and bridges declare what they connect; `combinations` maintains no module-name list. | Adding a feature or a bridge should not mean editing `combinations`. | Never | `combinations`' card; `guard` G22 (wirings), G25 (adapters) |
| Wirings ship as part of the product. Numeric parameters such as capacities are settings with defaults. The `templates` folder keeps its name. | The folder name is public. | Never | The wiring cards |
| Assembly happens in two passes. A contributing module that needs its owner's runtime interface uses a `kernel` late reference after assembly, or receives the interface as an extension point argument. | Some interfaces do not exist when contributions are built. | Never | `kernel`'s card |
| Conformance tests and declared differences compare against v0.17.0. | That is the release operators are moving from. | Never | The conformance modules' cards |
| A first second factor enrolled without a binding proof does not complete the login that enrolled it. It counts from the next sign-in. | v0.17.0 behaves this way. | Never | `mfa-enrollment`'s completion card |
| An owner's configuration section may contain contributor settings in its contribution list. For example, `federation`'s `idps.<name>` contains settings for that IdP type. If the owner has no composition module, use its default adapter's section. | Operators configure each contribution alongside its owner. | Never | `federation`'s card |
| G7 reports a unit whose dependency cards together pass their measure, without refusing it, and applies a lower card line limit to packages with many dependents. | To use a module, you also read the cards of what it depends on; those cards are not the unit's to change. | Never | `guard` G7 |
| The provider never terminates TLS: it serves plain HTTP, and TLS ends at a proxy in front of it. It accepts a forwarded client certificate only from a proxy it trusts. | Anyone else could forge the header. | Never | `http`'s and `client-certificate`'s cards; the security model |
| For each change, record the estimated and actual amount read, the contracts added and the modules changed. | Measurements show whether the structure reduces how much a change requires someone to read. | Never | The work records kept outside the repository |
| Each feature keeps its own wiring package; no single wiring is generated for all features. Keep each wiring's card to one paragraph, put pass-through tests in the feature where possible, and create the manifest from a template. | A wiring is reviewed and released together with its feature. | When there are more than 25 wiring packages, or measurements show wirings change often | The wiring cards |
| Requests do not wait for audit delivery, and receiver failures do not change their responses. Events must contain no tokens or secrets; include the subject when the event identifies one. Receivers are responsible for reliable storage. | A broken audit receiver must not take login down with it. | Never | `audit`'s card and public interface; the audit event reference |
| G7 counts workspace dependencies imported by each unit's shipped code, excluding common packages. | What shipped code imports is what a change to it can reach. | Never | `guard` G7 |
| Readiness probes are a `kernel` extension point. `kernel` runs them within a deadline and logs failures; the readiness response reports only ready or unready. The module owning each connection contributes its probe, and `http` serves the route contributed by `http-ops`. | Connection owners define the checks; readiness uses one deadline. | Never | `kernel`'s and `http-ops`' cards; the owner map |
| `kernel` owns log levels and their configuration. The levels match the legacy system, the setting is `logging.level`, and the default is `info`. A separate, replaceable module writes the logs. | Operators retain the legacy levels and choose a destination for their deployment. | Never | `kernel`'s card |
| `kernel`'s `./testing` provides a runtime with a clock, randomness and quiet logging, plus `quietLog` and `recordingLog`. Use these helpers in module tests instead of building replacements. | Tests share runtime helpers and avoid unnecessary log output. | Never | `kernel`'s card |
| An adapter names its owner in exactly one manifest field: `replaces` or `adapts`. When an owner has several adapters, exactly one says `default: true`. The owner never names its adapters. `guard` gets the kind names from `kinds`. | The adapter depends on its owner, not the other way round. | Never | `guard` G25; `guard-imports`' card |
| Features disabled by default in v0.17.0 declare `optIn: true`. The full template omits them unless another composed module needs them. Operators add them with `create-app --add`, which includes their wirings and bridges. | `create-app` needs no module-name list. | Never | `combinations`' and `create-app`'s cards |
| Mail-sending modules declare their purposes in `mailPurposes`. Each purpose's default wording comes from a separate adapter in plain English, which deployments may replace. | Deployments can customize wording without changing the sending module. | Never | `mail`'s card; the wording modules' cards |
| Treat stored records without `format` as format 1. Read the current format N and the previous format N−1; write N. Downgrades are unsupported. | Records written by one release stay readable after the next upgrade. | Never | The cards of modules that keep records |
| The module performing expensive work or background jobs sets concurrency and queue-length limits. Reject work over those limits before starting it; HTTP requests receive 503. | Only that module knows what the work costs. | Never | The cards of modules that do such work |
| Card limits have no module-specific exceptions. Split oversized cards by subject, using nested items or internal modules as appropriate. Do not compress the wording or raise the limits. | Everyone who depends on a module reads its whole card. | Never | `guard` G7 |
| Public-interface doc comments are part of the contract and are excluded from the implementation-comment limit. | The contract should be explained where it is declared. | Never | `guard` G7 |
| Everything in the repository is in English. The Japanese README is the only exception. | Readers can follow the code and documentation in one language. | Never | `CONTRIBUTING` |
| Outbound HTTP requests go through `outbound`, which applies `outbound-policy`'s destination, credential and request-limit policy. Other direct network access must be permitted by the package's manifest `network` declaration, as G26 requires. | The policy stays in one module, `outbound-policy`, and sending in one, `outbound`. | Never | `guard` G26 |
| A package that writes a narrower's `internal`, which lets a request reach a private address at the operator's own URL, declares `narrower`: `internal` in its own manifest and on its card; the narrower's owner states what it holds to declaration in its `narrowerOwner`, and names no package. G32 checks the code it reads against the declarations; the runtime decision stays the owner's, over the configured URL. | Each package owns the fact that it reaches private addresses, and adding one edits no other package's manifest; the list readers need is derived from the declarations. | Never | `guard-imports` G32 |
| When a store outage keeps a login from closing the sessions it pushed out over the cap, `session-lifecycle` lists each again for what it has left; one that cannot be, or that taking one back pushes out, is ended in its record without calling its participants. Access tokens issued in it stay valid until they expire, at most to the session's own end; the counts are logged, and revoking the subject ends them at once where `subject-tokens` is composed (`tokens.subject-check` is not `none`). Clients get no back-channel logout notice for such a session, then or at a later revocation. | No session may stay open off its subject's listing, where neither a revocation nor the cap reaches it, and the participants cannot be tracked while the store that keeps a close is failing. | Token verification checks that a token's session is still open, or a close can be kept while the listing cannot | `session-lifecycle`'s listing card; the [runbook](runbook.md#outages)'s Redis outages |
| A cryptographic choice made with an outside party (a signing or accepted algorithm, a TLS version and suite set) or kept in a long-lived record (a seal's algorithm) is a setting of the module that owns that wire or record. The specification's floor is the setting's type, and one implementation is enough to start with. A choice a specification fixes, or an internal hash or MAC of a random value or of one that lives briefly, has no setting, and the card says so. A choice below a specification's MUST is an explicit setting of the module that owns the wire, or a bare switch named `accept-*`, and it is warned of at every start. | A value found weak must be replaceable by configuration, without waiting for a release and without breaking deployments that still use it. | Never | The cards of the modules that own a wire or a record; `kernel`'s settings; `docs/attack-surface.md` (the switches that loosen a default) |
