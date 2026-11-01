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
	/** Its assertions are also taken for the token endpoint, or naming their audience in a list. */
	readonly looseAudience?: boolean;
	readonly grants: readonly string[];
	/** Every token it is issued must be sender-bound (`sender-binding`'s `required`); for scenes the legacy build is not asked. */
	readonly bindingRequired?: boolean;
	/** The binding kinds a required binding must be of, by the names operators give them (such as dpop); unwritten, any. Read only beside `bindingRequired`. */
	readonly bindingKinds?: readonly string[];
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

/** A ledger the issuer's assertions are used up in, shared with another service: its URL and token. */
export interface JtiLedgerScene {
	readonly consumeUrl: string;
	readonly credential: string;
	/** The header the token goes in as it is; unset, as a bearer Authorization. */
	readonly credentialHeader?: string;
}

export type TrustedIssuerScene = (
	| {
			readonly issuer: string;
			readonly alg: "EdDSA" | "ES256" | "RS256" | "PS256";
			readonly publicPem: string;
	  }
	/**
	 * Linked: its signers' keys asked of a ledger at `keysUrl`, the subject the user found by `upstream`.
	 * `thumbprint`: a signer's `sub` is its key's JWK thumbprint. `selfIssuedPrefix`: it takes too the
	 * self-issued signers whose `iss` and `sub` are the prefix and their key's thumbprint.
	 */
	| {
			readonly issuer: string;
			readonly linked: {
				readonly upstream: string;
				readonly keysUrl: string;
				readonly thumbprint?: true;
				readonly selfIssuedPrefix?: string;
			};
	  }
) & {
	/** Its assertions used up in this ledger in place of the store. */
	readonly jtiLedger?: JtiLedgerScene;
	/** Conditions its assertions' verified claims meet; an issuer with written keys and none takes any subject. */
	readonly conditions?: {
		readonly "subject-prefix"?: string;
		readonly claims?: Readonly<
			Record<string, string | number | boolean | readonly (string | number | boolean)[]>
		>;
	};
	/** The registered client its assertions identify where a request names none: public, method none. */
	readonly client?: string;
	/** Its assertions taken as ID-JAGs (preview): on the new target alone, as the legacy build takes no trusted issuer. */
	readonly profile?: "id-jag";
	/** A ceiling over what its assertions are issued, within the client's allowance. */
	readonly ceiling?: {
		readonly scopes?: readonly string[];
		readonly audiences?: readonly string[];
	};
};

/** Clients, the token endpoint and what is offered beside it; DPoP nonces named only beside DPoP. */
export type OauthPart = {
	readonly issuer: string;
	readonly clients: readonly ClientScene[];
	/** Token introspection (RFC 7662) for the clients. */
	readonly introspection?: boolean;
	/** Token revocation (RFC 7009) for the clients; access tokens can be revoked. */
	readonly revocation?: boolean;
	/** Issuers whose JWT assertions the jwt-bearer grant trusts; absent means no such grant, `false` a scene about that. */
	readonly jwtBearer?: { readonly issuers: readonly TrustedIssuerScene[] } | false;
	/** The provider's metadata document (RFC 8414, OpenID Connect Discovery). */
	readonly discovery?: boolean;
	/** `false`, a scene about the authorization endpoint's absence (`authorize`), which the area never composes itself. */
	readonly authorize?: false;
	/** No access token for a user whose account does not state the email verified; clients' own tokens still issue. */
	readonly verifiedEmail?: true;
	/** How the requests rate limit answers while the store fails; store-fault scenes let them by unless this says closed. */
	readonly rateLimitWhileStoreFails?: "open" | "closed";
	readonly resourceIndicators?: boolean;
} & (
	| {
			/** Sender-constrained tokens by DPoP (RFC 9449) at the token endpoint; `false`, a scene about their absence. */
			readonly dpop?: false;
			readonly dpopNonce?: never;
	  }
	| {
			readonly dpop: true;
			/** The token endpoint asks a nonce of each proof (RFC 9449 §8). Read only beside dpop. */
			readonly dpopNonce?: true;
	  }
);

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
