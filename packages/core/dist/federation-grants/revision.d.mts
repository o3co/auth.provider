import type { FederationGrantConnection } from "./types.mjs";
/**
 * Who the upstream is, and as whom auth.provider speaks to it.
 *
 * When this differs, the upstream subject the grant recorded can no longer be
 * compared — many IdPs issue a `sub` per client — so a reauthorization could
 * never pass its account check. The grant reads as
 * `connection_identity_changed`, and the application asks for a new one.
 */
export declare function federationGrantIdentityRevision(connection: Pick<FederationGrantConnection, "upstreamIssuer" | "upstreamClientId">): string;
/**
 * What is asked of the upstream, for which resource, in which environment.
 *
 * When this differs the grant reads as `reauthorization_required` /
 * `connection_changed` and is reauthorized in place. Narrowing the scopes
 * changes it too: reusing consent across a narrowing would be sound, but
 * proving "narrower" for every field is not worth it, and asking again is
 * always safe.
 *
 * `maxAccessTokenLifetime` and `allowScopeSubsets` are deliberately not here.
 * The first is judged against its current value before every disclosure, so
 * tightening it takes effect on the next call; making it part of this
 * fingerprint would turn a configuration slip into a reconnect for every
 * user. The second only governs what a new intent may ask for.
 */
export declare function federationGrantAuthorizationRevision(connection: Pick<FederationGrantConnection, "resource" | "scopes" | "boundary" | "authorizationParams">): string;
//# sourceMappingURL=revision.d.mts.map