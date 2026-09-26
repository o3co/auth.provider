import type { ProviderDeps } from "./provider.mjs";
import type { RouteContributionEntry } from "./route-contribution.mjs";
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
export type GrantFactory<Deps> = (deps: Deps) => GrantHandler;
export type FederationFactory<Deps> = (deps: Deps) => FederationProvider;
export type ExchangeTokenValidatorFactory<Deps> = (deps: Deps) => ExchangeTokenValidator;
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
    readonly grants?: {
        readonly [grantType: string]: GrantFactory<Deps>;
    };
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
//# sourceMappingURL=contributes-map.d.mts.map