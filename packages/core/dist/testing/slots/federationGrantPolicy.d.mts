/**
 * The test double of the `federationGrantPolicy` slot.
 * `createTestFederationGrantPolicy` answers grants off unless told
 * otherwise; it checks nothing, so a test of a broken value builds it here.
 * The contract suite is `@o3co/auth-provider-test-kit`'s. Published on
 * `@o3co/auth-provider-core/testing`.
 */
import type { FederationGrantPolicy } from "../../federation-grants/policy.mjs";
/** Grants off and nothing kept — unless `overrides` say otherwise — frozen. */
export declare function createTestFederationGrantPolicy(overrides?: Partial<FederationGrantPolicy>): FederationGrantPolicy;
//# sourceMappingURL=federationGrantPolicy.d.mts.map