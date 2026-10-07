/**
 * What the `/oauth` router resolves once, when it is built, and hands its
 * endpoints: the `oauth.*` options, read from the section `oauth` alone; the
 * acr table `/authorize` answers from, which also reads core's view of the
 * federations (`federationSettings`); the canonical issuer (one that is not
 * canonical refuses the build); and the one client repository every endpoint
 * looks a client up in, which reads registered clients through core's
 * client-record boundary and fetches a client's metadata document under
 * core's outbound policy (`outboundPolicy`).
 */
import { type ClientRepository, type ConsentStore, type FederationProvider, type FederationSettings, type Logger, type OutboundPolicy, type SessionRequirementResolver } from "@o3co/auth-provider-core";
import { vouchableAcrValues } from "./acrValues.mjs";
import { type ClientIdMetadataDocumentOptions } from "./clients/clientIdMetadataDocument.mjs";
import { type ResolvedOAuthOptions } from "./resolveOAuthOptions.mjs";
import { type AuthorizationResponse } from "./routes/authorizationResponse.mjs";
/** What {@link resolveRouterSettings} resolved. */
export interface RouterSettings {
    readonly options: ResolvedOAuthOptions;
    /** Undefined when `/authorize` is not mounted. */
    readonly acrTable: ReturnType<typeof vouchableAcrValues>["table"] | undefined;
    readonly canonicalIssuer: string;
    /** Builds every authorization response, its `iss` (RFC 9207) bound to `advertisedIssuer(canonicalIssuer)`. */
    readonly authorizationResponse: AuthorizationResponse;
    readonly clientRepository: ClientRepository;
}
export declare const resolveRouterSettings: ({ section, federationSettings, authorizationEndpoint, requirements, getFederationProviders, registeredClients, consentStore, outboundPolicy, clientIdMetadataDocumentSeams, logger, }: {
    /** `oauth {}`: every `oauth.*` option the router reads. */
    readonly section: unknown;
    /**
     * Core's view of `core.federations`, for what the acr table reads beyond
     * `oauth {}`: which installed federation trusts its upstream IdP's `amr`.
     */
    readonly federationSettings: FederationSettings;
    /** Whether `/authorize` is mounted. */
    readonly authorizationEndpoint: boolean;
    readonly requirements: SessionRequirementResolver;
    readonly getFederationProviders: () => ReadonlyMap<string, FederationProvider> | undefined;
    readonly registeredClients: ClientRepository;
    readonly consentStore: ConsentStore | undefined;
    /** Core's `outboundPolicy` slot (`core.outbound`): a metadata document is fetched under it. */
    readonly outboundPolicy: OutboundPolicy;
    readonly clientIdMetadataDocumentSeams: Pick<ClientIdMetadataDocumentOptions, "fetch" | "now">;
    readonly logger: Logger;
}) => RouterSettings;
//# sourceMappingURL=routerSettings.d.mts.map