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
import type { AuditSink } from "../../audit/types.mjs";
import type { OidcDiscoveryContribution } from "../../discovery/types.mjs";
import type { GrantHandler as ConcreteGrantHandler } from "../../grants/types.mjs";
import type { MfaProvider } from "../../mfa/types.mjs";
import type { TokenBindingMechanism } from "../../middleware/tokenBinding.mjs";
import type { GrantPolicyHook } from "../../policy/types.mjs";
import type { ProviderDeps } from "./provider.mjs";
import type { RouteContributionEntry } from "./route-contribution.mjs";

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
//   MfaFactor                   — MfaProvider interface at packages/core/src/mfa/types.mts (AS-M1)
//   GrantPolicyHookContribution — GrantPolicyHook interface at packages/core/src/policy/types.mts (AS-M1, AS-7 collision rename)
//   FederationProvider          — packages/session/src/federations/types.mts (Phase F deferred — circular import)
//   ExchangeTokenValidator      — packages/oauth-token-exchange/src/validator/types.mts (Phase F deferred — circular import)
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
 * Type produced by a `FederationFactory<Deps>` contribution. Still
 * `unknown` pending Phase F: substituting with `FederationProvider` from
 * `packages/session/src/federations/types.mts` requires resolving the
 * core ↔ session circular package import.
 */
export type FederationProvider = unknown;

/**
 * Type produced by an `ExchangeTokenValidatorFactory<Deps>` contribution.
 * Still `unknown` pending Phase F: substituting with `ExchangeTokenValidator`
 * from `packages/oauth-token-exchange/src/validator/types.mts` requires
 * resolving the core ↔ oauth-token-exchange circular package import.
 */
export type ExchangeTokenValidator = unknown;

/**
 * Type produced by an `MfaFactorFactory<Deps>` contribution. Substituted
 * in v0.5.1 (AS-M1) from the `unknown` placeholder to the canonical
 * `MfaProvider` interface from `packages/core/src/mfa/types.mts`.
 */
export type MfaFactor = MfaProvider;

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

export type GrantFactory<Deps> = (deps: Deps) => GrantHandler;
export type FederationFactory<Deps> = (deps: Deps) => FederationProvider;
export type ExchangeTokenValidatorFactory<Deps> = (deps: Deps) => ExchangeTokenValidator;
export type MfaFactorFactory<Deps> = (deps: Deps) => MfaFactor;
export type AuditHookFactory<Deps> = (deps: Deps) => AuditHook;
export type GrantPolicyHookFactory<Deps> = (deps: Deps) => GrantPolicyHookContribution;

/**
 * Factory type for the `discoveryMetadata` contribution kind.
 *
 * Returns a {@link OidcDiscoveryContribution} partial — the endpoints + literal fields
 * this module wants advertised in the OIDC `/.well-known/openid-configuration`
 * document. Core's `assembleApp` aggregates every module's contribution into
 * one document (issuer-gated). List-shaped: multiple modules contribute
 * (oauth its endpoints + capabilities, jwks its `jwks_uri`, …).
 */
export type OidcDiscoveryContributionFactory<Deps> = (deps: Deps) => OidcDiscoveryContribution;

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
export type GrantMiddlewareFactory<Deps> = (deps: Deps) => RequestHandler | null;

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
export type TokenBindingMechanismFactory<Deps> = (deps: Deps) => TokenBindingMechanism | null;

/**
 * Declaration-merged map of contribution kinds.
 *
 * Per A2-α §4.1 the v0.5.0 baseline declares 7 kinds. A5 (Phase 7) adds
 * `federationRedirectPolicies` via `declare module` augmentation in the
 * session package; consumer plugins may add custom kinds the same way.
 *
 * Per A2-α §4.5 collision policy:
 * - Name-keyed (`grants`, `federations`, `tokenExchangeValidators`,
 *   `mfaFactors`): throw on duplicate at boot (enforced in Phase 4 / A2-β).
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
	readonly tokenExchangeValidators?: {
		readonly [tokenType: string]: ExchangeTokenValidatorFactory<Deps>;
	};
	readonly mfaFactors?: {
		readonly [kind: string]: MfaFactorFactory<Deps>;
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
