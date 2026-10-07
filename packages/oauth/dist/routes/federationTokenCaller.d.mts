import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
/**
 * Steps 1 to 4: the token, its verification, and `family_id`, `sid` and
 * `azp`, each required. Returns the caller, or `null` once answered.
 */
export declare const identifyCaller: (ctx: FederationTokenContext) => Promise<FederationTokenCaller | null>;
//# sourceMappingURL=federationTokenCaller.d.mts.map