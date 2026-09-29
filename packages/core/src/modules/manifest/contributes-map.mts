/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import type { RequestHandler } from "express";
import type { z } from "zod";
import type { AuditSink } from "../../audit/types.mjs";
import type { OidcDiscoveryContribution } from "../../discovery/types.mjs";
import type { FederationProvider as ConcreteFederationProvider } from "../../federations/types.mjs";
import type { GrantHandler as ConcreteGrantHandler } from "../../grants/types.mjs";
import type { MfaFactor as ConcreteMfaFactor } from "../../mfa/factor.mjs";
import type { TokenBindingMechanism } from "../../middleware/tokenBinding.mjs";
import type { GrantPolicyHook } from "../../policy/types.mjs";
import type { RateLimitSpec } from "../../ratelimit/types.mjs";
import type { SessionRequirement as ConcreteSessionRequirement } from "../../session-admission/requirement.mjs";
import type { ExchangeTokenValidator as ConcreteExchangeTokenValidator } from "../../token-exchange/validator.mjs";
import type { Contributed } from "./contributed.mjs";
import type { ProviderDeps } from "./provider.mjs";
import type { RouteContributionEntry } from "./route-contribution.mjs";

// Re-exported so the vocabulary has one home and one path: a module author
// reads `Contributed` from the same place as the factory types that use it.
export type { Contributed };

// Domain-type substitution status (AS-M1 / Phase F F9 PR6).
//
// Per A2-α §4.1: each per-kind factory type produces a value owned by
// the package that declares the kind. The four kinds owned by `core`
// itself have been substituted from `unknown` placeholders to their
// concrete same-package types. The two cross-package kinds remain as
// `unknown` pending Phase F resolution of a circular-import concern
// (`session` and `oauth-token-exchange` are downstream of `core`, so
// importing their types from this file would create a package-level
// cycle).
//
//   GrantHandler                — packages/core/src/grants/types.mts:120 (concrete, AS-M1)
//   AuditHook                   — AuditSink interface at packages/core/src/audit/types.mts (AS-M1)
//   MfaFactor                   — the second-factor contract at packages/core/src/mfa/factor.mts (MFA ADR D3, D7)
//   GrantPolicyHookContribution — GrantPolicyHook interface at packages/core/src/policy/types.mts (AS-M1, AS-7 collision rename)
//   FederationProvider          — packages/core/src/federations/types.mts (#626 P1)
//   ExchangeTokenValidator      — packages/core/src/token-exchange/validator.mts (#626 P1)
//
// Canonical (no-suffix) interface names are used for the substitution
// RHS. The v0.5.1-era `*Base` deprecation aliases were removed
// (M2); references on this site are to the interfaces themselves.

/**
 * Type produced by a `GrantFactory<Deps>` contribution. Substituted in
 * v0.5.1 (AS-M1) from the `unknown` placeholder to the concrete
 * `GrantHandler` interface from `packages/core/src/grants/types.mts`.
 */
export type GrantHandler = ConcreteGrantHandler;

/**
 * Type produced by a `FederationFactory<Deps>` contribution: the adapter
 * port itself (#626 P1). It was `unknown` while the contract lived in
 * `packages/session`, which core may not import; the contract lives in
 * `../../federations/types.mts` now, so registration and use share one type.
 */
export type FederationProvider = ConcreteFederationProvider;

/**
 * Type produced by an `ExchangeTokenValidatorFactory<Deps>` contribution: the
 * validator contract itself (#626 P1). It was `unknown` while the contract
 * lived in `packages/oauth-token-exchange`, which core may not import; the
 * contract lives in `../../token-exchange/validator.mts` now.
 */
export type ExchangeTokenValidator = ConcreteExchangeTokenValidator;

/**
 * Type produced by an `MfaFactorFactory<Deps>` contribution: the contract a
 * second factor implements, in `packages/core/src/mfa/factor.mts` (the MFA
 * ADR's D7). The name survived the #69 surface's removal (D3) with this
 * meaning.
 */
export type MfaFactor = ConcreteMfaFactor;

/**
 * Type produced by a `SessionRequirementFactory<Deps>` contribution: the
 * requirement contract in `packages/core/src/session-admission/requirement.mts`
 * (the session-admission ADR's D3).
 */
export type SessionRequirement = ConcreteSessionRequirement;

/**
 * Type produced by an `AuditHookFactory<Deps>` contribution. Substituted
 * in v0.5.1 (AS-M1) from the `unknown` placeholder to the canonical
 * `AuditSink` interface from `packages/core/src/audit/types.mts`.
 */
export type AuditHook = AuditSink;

/**
 * Type produced by a `GrantPolicyHookFactory<Deps>` contribution.
 *
 * Renamed from `GrantPolicyHook` in v0.5.1 (AS-7 collision resolution):
 * the canonical `GrantPolicyHook` name now refers to the policy-package
 * interface at `packages/core/src/policy/types.mts`. Substituted in
 * v0.5.1 (AS-M1) from the `unknown` placeholder to that canonical
 * interface — a contribution factory now produces a concrete
 * grant-policy-hook adapter rather than an opaque value.
 */
export type GrantPolicyHookContribution = GrantPolicyHook;

// Per-kind factory types — each follows `(deps: Deps) => Value` per A2-α §4.1.

export type GrantFactory<Deps> = (deps: Deps) => Contributed<GrantHandler>;
export type FederationFactory<Deps> = (deps: Deps) => Contributed<FederationProvider>;

/**
 * One configured federation as a type's factory receives it (#728): the name
 * the operator gave it — the `:name` of its login route, and the name the
 * provider registers under — and its entry, parsed by the type's
 * `entrySchema`.
 */
export interface FederationInstance<E> {
	readonly name: string;
	readonly entry: E;
}

/**
 * A `federationTypes` entry (#728): what one federation package handles,
 * keyed by the `type` an entry of the `federations` configuration names
 * (`"oidc"`, `"google"`). #728 makes one module per federation package
 * register one federation per configured entry of its type, and creates no
 * module from configuration; this is what that dispatch reads — the schema
 * an entry of the type is parsed with, and the factory that builds a
 * provider from one entry and its name.
 *
 * Not dispatched yet: boot registers the declaration under its type — so two
 * packages claiming one type are `duplicate-contribute` — and parses no entry
 * and calls no factory until the federations section moves under core.
 *
 * `E` is the entry's type. Author a declaration with `defineFederationType`
 * (`define-federation-type.mts`), which infers `E` from `entrySchema` and
 * types the factory's entry with it, so a schema and a factory that disagree
 * do not compile. Written inline in a module without it, `E` is `unknown` —
 * the kind's record cannot carry a type per key, and the factory is a method,
 * bivariant in its entry — so nothing ties an annotated entry to the schema.
 *
 * Boot reads a declaration's schema and factory once, at stage 1; what it
 * registers closes over those, so changing the declaration afterwards changes
 * neither.
 */
export interface FederationTypeContribution<Deps, E = unknown> {
	/**
	 * The schema of an entry of this type: the keys the adapter reads. The
	 * map's owner strips its own keys — those every entry carries whatever its
	 * type (`enabled`, `type`, `trustUpstreamAmr`) — before it parses an entry
	 * with this schema, so a strict schema names only the type's keys.
	 */
	readonly entrySchema: z.ZodType<E>;
	/**
	 * Builds the provider for one configured entry of this type, given the
	 * module's deps and the entry with its name; the provider registers under
	 * that name.
	 */
	factory(deps: Deps, instance: FederationInstance<E>): Contributed<FederationProvider>;
}
export type ExchangeTokenValidatorFactory<Deps> = (
	deps: Deps,
) => Contributed<ExchangeTokenValidator>;
/**
 * An `mfaFactors` entry. It answers `null` when the factor is switched off by
 * its configuration, as a `TokenBindingMechanismFactory` does; the kind is
 * then absent from `mfaFactorResolver`, and still claimed — a second
 * contribution of it is a duplicate.
 */
export type MfaFactorFactory<Deps> = (deps: Deps) => Contributed<MfaFactor | null>;
/**
 * A `sessionRequirements` entry (the session-admission ADR's D3): a
 * requirement every consumer of a browser session asks through admission,
 * keyed by its `name`. Never `null`: a requirement is switched off by not
 * installing it, so nothing can quietly remove one from behind the
 * consumers. Its `reach` may be a getter: it is read after the name-keyed
 * pass, never at registration.
 */
export type SessionRequirementFactory<Deps> = (deps: Deps) => Contributed<SessionRequirement>;
export type AuditHookFactory<Deps> = (deps: Deps) => Contributed<AuditHook>;
export type GrantPolicyHookFactory<Deps> = (deps: Deps) => Contributed<GrantPolicyHookContribution>;

/**
 * Factory type for the `discoveryMetadata` contribution kind.
 *
 * Returns a {@link OidcDiscoveryContribution} partial — the endpoints + literal fields
 * this module wants advertised in the OIDC `/.well-known/openid-configuration`
 * document. Core's `assembleApp` aggregates every module's contribution into
 * one document (issuer-gated). List-shaped: multiple modules contribute
 * (oauth its endpoints + capabilities, jwks its `jwks_uri`, …).
 */
export type OidcDiscoveryContributionFactory<Deps> = (
	deps: Deps,
) => Contributed<OidcDiscoveryContribution>;

/**
 * Factory type for the `grantMiddleware` contribution kind.
 *
 * Returns an Express `RequestHandler` to mount on the OAuth token endpoint
 * (`/oauth/token` with the bundled `oauthModule`) BEFORE grant dispatch, or
 * `null` when the mechanism is disabled by config (e.g.
 * `oauth.dpop.enabled = false`). Null-returning factories are skipped at
 * composition time — they are never mounted.
 *
 * Per Wave 2 Token-binding Cluster spec §4.7 / Phase 2 DPoP spec §11.1.
 */
export type GrantMiddlewareFactory<Deps> = (deps: Deps) => Contributed<RequestHandler | null>;

/**
 * Factory type for the `tokenBindingMechanisms` contribution kind.
 *
 * Returns a `TokenBindingMechanism` to be composed into the single
 * `tokenBindingMw` instance mounted by core on the OAuth token endpoint,
 * or `null` when the mechanism is disabled by config (e.g.
 * `oauth.dpop.enabled = false`). Null-returning factories are filtered at
 * composition time — they never contribute to the synthesized middleware.
 *
 * Unlike `grantMiddleware`, which contributes a pre-composed middleware
 * (each module owning its own `tokenBindingMw`), `tokenBindingMechanisms`
 * contributes raw mechanisms so that core can compose ONE `tokenBindingMw`
 * across all modules. This lets the configured `DispatchPolicy`
 * (`intent-explicit` / `strict-mutual-exclusion`) arbitrate cross-module
 * when multiple mechanism modules (DPoP, mTLS, ...) are installed.
 *
 * See ADR `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`
 * for the cross-mechanism design rationale.
 */
export type TokenBindingMechanismFactory<Deps> = (
	deps: Deps,
) => Contributed<TokenBindingMechanism | null>;

/**
 * A `rateLimitBudgets` entry (#728): the budget of one rate-limit prefix the
 * contributing module owns — the default limit and window a limiter applies
 * to keys under that prefix, which the module reads from its own settings.
 *
 * The budget is numbers, already parsed: read the settings through the
 * module's own schema (coercing what an environment variable substitutes as
 * a string) or `requireUsableConfiguredRateLimitSpec`, because a budget is
 * held to `isUsableRateLimitSpec` as answered, and `"20"` is not a limit.
 *
 * It answers `null` when the module's settings switch that budget off; the
 * prefix is then absent from `rateLimitBudgetResolver`, and still claimed —
 * a second contribution of it is a duplicate. Absent from the view is not
 * unlimited: a key under the prefix falls to the limiter's `defaultLimit`.
 */
export type RateLimitBudgetFactory<Deps> = (deps: Deps) => Contributed<RateLimitSpec | null>;

/**
 * Declaration-merged map of contribution kinds.
 *
 * Per A2-α §4.1 the v0.5.0 baseline declares 7 kinds. A5 (Phase 7) adds
 * `federationRedirectPolicies` via `declare module` augmentation in the
 * session package; consumer plugins may add custom kinds the same way.
 *
 * Per A2-α §4.5 collision policy:
 * - Name-keyed (`grants`, `federations`, `tokenExchangeValidators`,
 *   `mfaFactors`, `sessionRequirements`, `rateLimitBudgets`,
 *   `federationTypes`): throw on duplicate at boot (enforced in Phase 4 /
 *   A2-β).
 * - List-shaped (`auditHooks`, `routes`, `grantPolicyHooks`,
 *   `grantMiddleware`): allow duplicates; routes additionally throw on
 *   duplicate `id` / undecorated-mountPath collisions.
 *
 * Per A2-α §4.2 every contribution factory shares the declaring module's
 * top-level `requires` / `optional` typed Deps object — there is no
 * per-contribution dep declaration.
 */
export interface ContributesMap<Deps = ProviderDeps<never, never>> {
	readonly grants?: { readonly [grantType: string]: GrantFactory<Deps> };
	readonly federations?: {
		readonly [name: string]: FederationFactory<Deps>;
	};
	/**
	 * Federation types (#728), name-keyed by the `type` an entry of the
	 * `federations` configuration names: each package declares the schema of
	 * such an entry and the factory that builds a provider from one entry
	 * ({@link FederationTypeContribution}). Two packages claiming one type
	 * refuse boot (`duplicate-contribute`); a declaration that is not an object
	 * with an `entrySchema` and a `factory` refuses it at stage 1
	 * (`contribution-malformed`); a host may not supply the collector
	 * (`contribution-kind-guarded`). Not dispatched yet.
	 */
	readonly federationTypes?: {
		readonly [type: string]: FederationTypeContribution<Deps>;
	};
	readonly tokenExchangeValidators?: {
		readonly [tokenType: string]: ExchangeTokenValidatorFactory<Deps>;
	};
	readonly mfaFactors?: {
		readonly [kind: string]: MfaFactorFactory<Deps>;
	};
	/**
	 * Session requirements (the session-admission ADR's D3), name-keyed:
	 * projected by the synthetic key `sessionRequirementResolver`, which every
	 * consumer of admission requires. Neither overridable (stage 1's
	 * `session-requirement-kind-guard`) nor replaceable by a host collector
	 * (`createApp`, before the kinds are merged).
	 */
	readonly sessionRequirements?: {
		readonly [name: string]: SessionRequirementFactory<Deps>;
	};
	/**
	 * Rate-limit budgets (#728), a record name-keyed by the prefix a limiter key
	 * carries before its first `:` (`login` for `login:ip:<ip>`): each module
	 * contributes the budgets of the prefixes it owns, and core composes them
	 * into one view, the synthetic key `rateLimitBudgetResolver`, which a
	 * limiter reads at request time. Two modules contributing one prefix
	 * refuse boot (`duplicate-contribute`); a prefix no key can carry — empty,
	 * or holding `:` — refuses it at stage 1 (`contribution-malformed`), and a
	 * budget no limiter can apply as written fails its contribution; a host
	 * may not supply the collector (`contribution-kind-guarded`).
	 */
	readonly rateLimitBudgets?: {
		readonly [prefix: string]: RateLimitBudgetFactory<Deps>;
	};
	readonly auditHooks?: readonly AuditHookFactory<Deps>[];
	readonly routes?: readonly RouteContributionEntry<Deps>[];
	readonly grantPolicyHooks?: readonly GrantPolicyHookFactory<Deps>[];
	/**
	 * Express middleware mounted on the OAuth token endpoint (`/oauth/token`
	 * with the bundled `oauthModule`) BEFORE grant dispatch (Wave 2
	 * Token-binding Cluster spec §4.7 — added in Phase 1 retro for the
	 * tokenBindingMw composition surface).
	 *
	 * Use cases: token-binding middleware (DPoP, mTLS), custom rate-
	 * limiters, request body pre-processing. Factories that return `null`
	 * are skipped at composition time (typical when a mechanism is
	 * disabled by config).
	 *
	 * List-shaped — multiple modules may contribute. Composition order is
	 * module-registration order. Within one middleware factory the
	 * `DispatchPolicy` configured on `tokenBindingMw` decides which
	 * mechanism wins.
	 *
	 * Cross-contribution composition is plain Express middleware ordering
	 * — `tokenBindingMw` unconditionally assigns `req.tokenBinding` when it
	 * resolves a binding (no guard against an already-populated field), so
	 * a later `grantMiddleware` contribution that resolves a binding will
	 * **overwrite** the earlier one. Modules that need deterministic
	 * dispatch across competing mechanisms should compose them into a
	 * single `tokenBindingMw` call (where `DispatchPolicy` arbitrates)
	 * rather than register each mechanism as its own `grantMiddleware`
	 * factory.
	 */
	readonly grantMiddleware?: readonly GrantMiddlewareFactory<Deps>[];
	/**
	 * Mechanism contributions composed by core into a single
	 * `tokenBindingMw` instance mounted on the OAuth token endpoint
	 * (`/oauth/token` with the bundled `oauthModule`) BEFORE grant dispatch.
	 *
	 * Use this — NOT `grantMiddleware` — when a module ships a token-binding
	 * mechanism (DPoP, mTLS, future). Core's `assembleApp` collects all
	 * contributions, filters nulls, and composes one `tokenBindingMw` with
	 * the configured `DispatchPolicy` arbitrating cross-module:
	 *
	 * - `intent-explicit` (default): explicit-intent mechanisms (DPoP) win
	 *   over ambient mechanisms (mTLS) on a single request. ≥2 explicit-
	 *   intent mechanisms succeeding → 400 `invalid_request`.
	 * - `strict-mutual-exclusion`: any 2+ mechanisms succeeding → 400
	 *   `invalid_request`.
	 *
	 * The dispatch-policy comes from
	 * `config.oauth.tokenBinding.dispatch-policy` (declared by core's
	 * bundled config schema).
	 *
	 * List-shaped — multiple modules may contribute. Within a single module
	 * a factory typically returns one mechanism (or `null` when disabled by
	 * config), but the list is allowed to contain multiple factories to
	 * support a single module shipping multiple mechanisms.
	 *
	 * See ADR `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`
	 * for the cross-mechanism design rationale.
	 */
	readonly tokenBindingMechanisms?: readonly TokenBindingMechanismFactory<Deps>[];
	/**
	 * OIDC discovery metadata contributions. List-shaped — each endpoint-owning
	 * module contributes the endpoints + literal fields it wants advertised, and
	 * core's `assembleApp` aggregates them into the single
	 * `/.well-known/openid-configuration` document (mounted only when an issuer
	 * is configured). The aggregator owns `issuer` and
	 * `id_token_signing_alg_values_supported`; contributions supply issuer-
	 * relative `endpoints` (e.g. `authorization_endpoint`, `jwks_uri`) and
	 * literal `metadata` (capability arrays, logout flags). See
	 * `core/src/discovery/buildDocument.mts` for the merge + validation rules.
	 */
	readonly discoveryMetadata?: readonly OidcDiscoveryContributionFactory<Deps>[];
}
