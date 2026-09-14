import type { OrderedRouteContribution } from "../boot/types.mjs";
import type { ExchangeTokenValidator, FederationProvider, GrantHandler } from "../modules/manifest/contributes-map.mjs";
/**
 * Read-only inspection surface for tests. Per A2-γ §7.2: NEVER exposed on the
 * production AppHandle. The `createTestApp` factory attaches an instance of
 * this interface to the returned handle for fixture noise reduction.
 *
 * Stability: additive evolution only. Adding new entries is a minor; signature
 * changes on existing entries are major.
 */
export interface TestInspect {
    readonly grants: ReadonlyMap<string, GrantHandler>;
    readonly federations: ReadonlyMap<string, FederationProvider>;
    readonly tokenExchangeValidators: ReadonlyMap<string, ExchangeTokenValidator>;
    readonly routes: readonly OrderedRouteContribution[];
}
//# sourceMappingURL=test-inspect.d.mts.map