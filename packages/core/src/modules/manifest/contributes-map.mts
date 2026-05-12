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

import type { AuditSink } from "../../audit/types.mjs";
import type { GrantHandler as ConcreteGrantHandler } from "../../grants/types.mjs";
import type { MfaProvider } from "../../mfa/types.mjs";
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
// RHS. The v0.5.1-era `*Base` deprecation aliases were removed at v0.6.0
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
 * Declaration-merged map of contribution kinds.
 *
 * Per A2-α §4.1 the v0.5.0 baseline declares 7 kinds. A5 (Phase 7) adds
 * `federationRedirectPolicies` via `declare module` augmentation in the
 * session package; consumer plugins may add custom kinds the same way.
 *
 * Per A2-α §4.5 collision policy:
 * - Name-keyed (`grants`, `federations`, `tokenExchangeValidators`,
 *   `mfaFactors`): throw on duplicate at boot (enforced in Phase 4 / A2-β).
 * - List-shaped (`auditHooks`, `routes`, `grantPolicyHooks`): allow
 *   duplicates; routes additionally throw on duplicate `id` /
 *   undecorated-mountPath collisions.
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
}
