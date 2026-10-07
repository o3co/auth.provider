/**
 * `federationGrants.connections.<name>` read into the connections the domain
 * rules take (#593, D4/D6/D15).
 *
 * Core's `FederationGrantConnection` says reading it from configuration is the
 * package's job, and this is that job. Everything it refuses, it refuses at
 * boot, for one reason repeated: what a connection decides — which upstream
 * account a grant is pinned to, how much residual access it may carry, which
 * environment it belongs to — is decided once, at the moment a user consents,
 * and then lives for as long as the grant does. A misconfiguration found at
 * the first request has already been written into somebody's grant.
 */
import type { FederationGrantConnection } from "@o3co/auth-provider-core";
/**
 * Every configured connection, joined with the federation it points at.
 *
 * An empty map is valid and so is an absent one: removing the last connection
 * has to remain an operable change, and a deployment with none still answers
 * about the grants it already has.
 */
export declare function resolveFederationGrantConnections(config: unknown): ReadonlyMap<string, FederationGrantConnection>;
//# sourceMappingURL=connections.d.mts.map