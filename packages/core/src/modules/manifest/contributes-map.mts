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

import type { ProviderDeps } from "./provider.mjs";
import type { RouteContributionEntry } from "./route-contribution.mjs";

// Domain-type placeholders.
//
// Per A2-α §4.1: each per-kind factory type produces a value owned by
// the package that declares the kind. Phase 9 substitutes the concrete
// types when the federation, oauth, and oauth-token-exchange packages
// migrate to manifest shape. For now, structural placeholders avoid
// circular package imports.
//
// Inventory of concrete types (paths verified 2026-04-28):
//   GrantHandler       — packages/core/src/grants/types.mts:67
//   FederationProvider — packages/session/src/federations/types.mts:69
//   ExchangeTokenValidator — packages/oauth-token-exchange/src/validator/types.mts:26
//   MfaFactor          — no dedicated interface found; mfa uses MfaProviderBase
//                        (packages/core/src/mfa/types.mts). Phase 9 clarifies.
//   AuditHook          — AuditSinkBase at packages/core/src/audit/types.mts:38
//   GrantPolicyHook    — GrantPolicyHookBase at packages/core/src/policy/types.mts:50

/**
 * Structural placeholder for GrantHandler. Phase 9 substitutes the concrete
 * type from packages/core/src/grants/types.mts.
 */
export type GrantHandler = unknown;

/**
 * Structural placeholder for FederationProvider. Phase 9 substitutes the
 * concrete type from packages/session/src/federations/types.mts.
 */
export type FederationProvider = unknown;

/**
 * Structural placeholder for ExchangeTokenValidator. Phase 9 substitutes the
 * concrete type from packages/oauth-token-exchange/src/validator/types.mts.
 */
export type ExchangeTokenValidator = unknown;

/**
 * Structural placeholder for MfaFactor. Phase 9 substitutes the concrete
 * type; the mfa package uses MfaProviderBase as the extension interface.
 */
export type MfaFactor = unknown;

/**
 * Structural placeholder for AuditHook. Phase 9 substitutes the concrete
 * type from packages/core/src/audit/types.mts (AuditSinkBase).
 */
export type AuditHook = unknown;

/**
 * Structural placeholder for GrantPolicyHook. Phase 9 substitutes the
 * concrete type from packages/core/src/policy/types.mts (GrantPolicyHookBase).
 */
export type GrantPolicyHook = unknown;

// Per-kind factory types — each follows `(deps: Deps) => Value` per A2-α §4.1.

export type GrantFactory<Deps> = (deps: Deps) => GrantHandler;
export type FederationFactory<Deps> = (deps: Deps) => FederationProvider;
export type ExchangeTokenValidatorFactory<Deps> = (
  deps: Deps,
) => ExchangeTokenValidator;
export type MfaFactorFactory<Deps> = (deps: Deps) => MfaFactor;
export type AuditHookFactory<Deps> = (deps: Deps) => AuditHook;
export type GrantPolicyHookFactory<Deps> = (deps: Deps) => GrantPolicyHook;

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
