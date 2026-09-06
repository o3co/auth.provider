import type { ExchangeTokenValidator, FederationProvider, GrantHandler } from "./contributes-map.mjs";
/**
 * Read-only projection of the boot planner's `grants` collector, exposed
 * to route factories that dispatch by `grant_type` at request time. Per
 * A2-α §6.5 + Amendment 3.
 *
 * The boot planner instantiates this resolver during `applyContributions`
 * (Phase 4 / A2-β §5.4) and freezes the underlying registry; the resolver
 * exposes only `get` and `entries`, no write surface.
 */
export interface GrantHandlerResolver {
    readonly get: (grantType: string) => GrantHandler | undefined;
    readonly entries: () => IterableIterator<readonly [string, GrantHandler]>;
}
/**
 * Read-only projection of the boot planner's `tokenExchangeValidators`
 * collector. Per A2-α §6.5.
 */
export interface TokenExchangeValidatorResolver {
    readonly get: (tokenType: string) => ExchangeTokenValidator | undefined;
    readonly entries: () => IterableIterator<readonly [string, ExchangeTokenValidator]>;
}
/**
 * Re-export of FederationProvider for downstream consumers that need the
 * structural placeholder. The concrete type is wired in Phase 9 when the
 * federation packages migrate to manifest shape.
 */
export type { FederationProvider };
/**
 * The set of synthetic ComponentMap keys at v0.5.0. The boot planner
 * (Phase 4 / A2-β §5.1 step 3) consults this set to reject:
 * - any module's `provides[K]` where `K ∈ SYNTHETIC_COMPONENT_KEYS`
 * - any `bootstrapComponents[K]`
 * - any `overrideComponents[K]`
 *
 * A5 (Phase 7) added `federationRedirectPolicyResolver` — the synthetic
 * projection for `federationRedirectPolicies` contributions (typed in
 * `@o3co/auth-provider-session/src/federations/contributes.mts`).
 *
 * Per A2-α §6.5 NORMATIVE constraints. The PRIMARY immutability guard
 * is the TypeScript declared type `ReadonlySet<string>` — `.add()`,
 * `.delete()`, and `.clear()` are prevented at compile time. The
 * runtime `Object.freeze` call additionally marks the Set object as
 * frozen (no new own properties, no prototype change), but it does
 * NOT prevent the built-in Set methods from mutating the internal
 * `[[SetData]]` slot — that is a JavaScript engine constraint specific
 * to built-in collection types. A consumer casting `(s as Set<string>)`
 * to mutate is explicitly bypassing the public type contract.
 */
export declare const SYNTHETIC_COMPONENT_KEYS: ReadonlySet<string>;
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        readonly grantHandlerResolver?: GrantHandlerResolver;
        readonly tokenExchangeValidatorResolver?: TokenExchangeValidatorResolver;
        readonly federationProviders?: ReadonlyMap<string, FederationProvider>;
    }
}
//# sourceMappingURL=synthetic-keys.d.mts.map