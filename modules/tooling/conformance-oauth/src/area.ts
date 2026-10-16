import { type AreaScene, area, sceneOf } from "@mod/conformance";
import { type KeysPart, keysArea } from "@mod/conformance-keys";

export interface ClientScene {
	readonly id: string;
	readonly kind: "public" | "confidential";
	readonly method: "client_secret_basic" | "client_secret_post" | "none" | "private_key_jwt";
	/** The secret, which each target keeps in its own way. */
	readonly secret?: string;
	/** A hash of the secret (bcrypt), which each target keeps as given. */
	readonly secretHash?: string;
	/** Public keys (JWKs) for the client's assertions, under `private_key_jwt`. */
	readonly keys?: readonly Readonly<Record<string, unknown>>[];
	/** Where the client publishes those keys instead, under `private_key_jwt`; plain http on loopback only. */
	readonly jwksUri?: string;
	readonly grants: readonly string[];
	readonly scopes: readonly string[];
	readonly defaultScopes?: readonly string[];
	readonly audiences?: readonly string[];
	/** Where the client receives authorization answers. */
	readonly redirectUris?: readonly string[];
	/** Run by the operator, and so never asked for consent. */
	readonly firstParty?: boolean;
	/** Receives the upstream tokens of its users' federation logins, with where an upstream logout may return. */
	readonly upstreamTokens?: { readonly postLogoutRedirectUris: readonly string[] };
	/** Holds federation grants: the connections it may ask for, and where a browser may be sent back. */
	readonly federationGrants?: {
		readonly connections: readonly string[];
		readonly returnUris: readonly string[];
	};
	/** Where a logout it starts may return, and where it is told a session ended, in a frame and by a post. */
	readonly logout?: {
		readonly postLogoutRedirectUris?: readonly string[];
		readonly frontchannelLogoutUri?: string;
		readonly frontchannelLogoutSessionRequired?: boolean;
		readonly backchannelLogoutUri?: string;
		readonly backchannelLogoutSessionRequired?: boolean;
	};
}

export interface TrustedIssuerScene {
	readonly issuer: string;
	readonly alg: "EdDSA" | "ES256" | "RS256";
	readonly publicPem: string;
}

/** Clients, the token endpoint and what is offered beside it. */
export interface OauthPart {
	readonly issuer: string;
	readonly clients: readonly ClientScene[];
	/** Token introspection (RFC 7662) for the clients. */
	readonly introspection?: boolean;
	/** Token revocation (RFC 7009) for the clients; access tokens can be revoked. */
	readonly revocation?: boolean;
	/** Issuers whose JWT assertions the jwt-bearer grant trusts; absent means no such grant, `false` a scene about that. */
	readonly jwtBearer?: { readonly issuers: readonly TrustedIssuerScene[] } | false;
	/** Sender-constrained tokens by DPoP (RFC 9449) at the token endpoint; `false`, a scene about their absence. */
	readonly dpop?: boolean;
	/** The provider's metadata document (RFC 8414, OpenID Connect Discovery). */
	readonly discovery?: boolean;
	/** No access token for a user whose account does not state the email verified; clients' own tokens still issue. */
	readonly verifiedEmail?: true;
	/** How the requests rate limit answers while the store fails; store-fault scenes let them by unless this says closed. */
	readonly rateLimitWhileStoreFails?: "open" | "closed";
	readonly resourceIndicators?: boolean;
}

export const oauthArea = area<OauthPart>("oauth");

/** A scene of keys and the OAuth part, in the shape the scenes write them. */
export function oauthScene(
	scene: OauthPart & {
		readonly keys?: KeysPart;
		readonly acceptVolatileStore?: boolean;
		readonly storeFaults?: boolean;
	},
): AreaScene {
	const { keys, acceptVolatileStore, storeFaults, ...part } = scene;
	return {
		...sceneOf(...(keys ? [keysArea.part(keys)] : []), oauthArea.part(part)),
		...(acceptVolatileStore === undefined ? {} : { acceptVolatileStore }),
		...(storeFaults === undefined ? {} : { storeFaults }),
	};
}
