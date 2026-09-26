/**
 * What a deployment must have configured before it may create grants (#593
 * slice 6, D6–D8), resolved once, at boot.
 *
 * Every refusal here is one a user would otherwise meet at the end of a
 * consent — standing in front of a page that cannot be shown, or coming back
 * from the upstream to a callback that was never going to accept them. Those
 * are the worst places to find out a deployment was not set up to finish what
 * it started, so they are found out here.
 */
import type { FederatedIdentityRegistration, FederationGrantAcquisitionConnection, FederationGrantConnection, FederationGrantIntentStore, UserRepository } from "@o3co/auth-provider-core";
/** Where the connect flow's callback route lives under the provider's origin. */
export declare const FEDERATION_GRANT_CALLBACK_PATH = "/session/federation-grants/callback/";
export type FederationGrantIdentityLookup = "required" | "unsupported";
export interface FederationGrantAcquisitionSettings {
    /** The deployment's consent page, as configured: a path, or an absolute URL on {@link origin}. */
    readonly consentUrl: string;
    /** Where connect sends a browser that is not signed in: `endpoints.login.url`. */
    readonly loginUrl: string;
    readonly identityLookup: FederationGrantIdentityLookup;
    /** The provider's browser-facing origin — the issuer's — never a request header. */
    readonly origin: string;
    /** Every configured connection, each with the callback its flow returns to. */
    readonly connections: ReadonlyMap<string, FederationGrantAcquisitionConnection>;
}
export declare function resolveFederationGrantAcquisitionSettings(config: unknown, connections: ReadonlyMap<string, FederationGrantConnection>): FederationGrantAcquisitionSettings;
/**
 * The registration an identity arriving through `connection` was issued
 * under, as the Store is asked about it (#611) — at boot, whether it covers
 * it, and in the callback, who holds an identity from it. Configuration only:
 * the federation's name, its configured issuer and the client it was issued to.
 */
export declare function federationGrantIdentityRegistration(connection: Pick<FederationGrantConnection, "federation" | "upstreamIssuer" | "upstreamClientId">): FederatedIdentityRegistration;
/**
 * D7 check 5 asks whether the upstream identity is already another local
 * user's, which needs a lookup the Store port has only optionally. `"required"`
 * — the default — refuses to boot without it; `"unsupported"` is the recorded
 * decision to skip that one check, and it is recorded in the audit of every
 * acquisition rather than taken silently.
 *
 * #611: having the method is not enough. A lookup that can see only the
 * namespace it is handed answers "linked to nobody" for an identity from a
 * registration no login linked under — D19's dedicated registration, whose
 * pairwise `sub` no login ever saw — and `"required"` would be satisfied by a
 * check that cannot see the answer. So the Store says, per connection's
 * registration, whether it covers it, and anything but a literal `true` is
 * refused here rather than met by every user who connects. With no connection
 * configured nothing is required, not even the methods: removing the last one
 * must stay operable on any repository.
 */
export declare function requireFederationGrantIdentityLookup(mode: FederationGrantIdentityLookup, userRepository: Partial<Pick<UserRepository, "findSubjectByFederatedIdentity" | "supportsFederatedIdentityLookup">> | undefined, connections: ReadonlyMap<string, FederationGrantConnection>): void;
export declare function requireFederationGrantIntentStore(store: FederationGrantIntentStore | undefined): FederationGrantIntentStore;
//# sourceMappingURL=acquisitionSettings.d.mts.map