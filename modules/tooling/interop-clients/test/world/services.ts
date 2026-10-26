import { generateKeyPairSync } from "node:crypto";
import type { AreaScene, Started } from "@mod/conformance";
import { type ClientScene, oauthScene } from "@mod/conformance-oauth";
import { fronted, signing } from "./fronted.ts";
import { type PlayedIdp, startPlayedIdp } from "./idp.ts";
import type { WorldClient } from "./world.ts";

/** The provider services meet (the `a2a` pattern's app): no user, session or login. */
export interface ServicesWorld {
	readonly issuer: string;
	readonly ca: string;
	readonly clients: Readonly<Record<"bearer" | "agents" | "jagAgent", WorldClient>>;
	/** The enterprise IdP the harness plays, whose ID-JAGs the provider takes (`profile = id-jag`). */
	readonly idp: Pick<PlayedIdp, "issuer" | "ca" | "otherwise" | "issued">;
	/** The issuer whose JWT assertions the jwt-bearer grant trusts, with its private key as a JWK. */
	readonly assertionIssuer: {
		readonly issuer: string;
		readonly privateJwk: Readonly<Record<string, unknown>>;
	};
	/**
	 * The issuer whose assertions a request naming no client presents, for its entry's client
	 * (`agents`): an RS256 key, as a JWK with no kid and as PKCS#8 PEM, its subjects under `agents/`.
	 */
	readonly clientlessIssuer: {
		readonly issuer: string;
		readonly privateJwk: Readonly<Record<string, unknown>>;
		readonly privatePem: string;
		readonly subjectPrefix: string;
	};
	stop(): Promise<void>;
}

const bearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const assertionIssuer = "https://assertions.example";
const clientlessIssuer = "https://agents.example";

/**
 * Starts the provider services meet, behind its front: a client allowed the jwt-bearer grant, and
 * an issuer whose assertions it trusts. A grant without a session has no source to vouch for a
 * user's email, so it is no grant of the full template's app, whose users are a ledger's.
 */
export async function startServicesWorld(
	given: { readonly start?: (scene: AreaScene) => Promise<Started>; readonly under?: string } = {},
): Promise<ServicesWorld> {
	const signer = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const idp = await startPlayedIdp(given.under);
	// The client an ID-JAG names: confidential, as the profile asks, and allowed the grant.
	const jagAgent = {
		id: "jag-agent",
		method: "client_secret_post",
		secret: "jag-agent-secret-0123456789abcdef",
	} as const;
	const jagClient: ClientScene = {
		id: jagAgent.id,
		kind: "confidential",
		method: jagAgent.method,
		secret: jagAgent.secret,
		grants: [bearerGrant],
		scopes: ["read"],
		defaultScopes: ["read"],
	};
	// RS256, the one algorithm golang.org/x/oauth2/jwt signs with.
	const agentsSigner = generateKeyPairSync("rsa", { modulusLength: 2048 });
	// The client a request naming none is taken for (RFC 7523 §3.1): public, no credential, this grant alone.
	const agents: ClientScene = {
		id: "agents",
		kind: "public",
		method: "none",
		grants: [bearerGrant],
		scopes: ["read"],
		defaultScopes: ["read"],
	};
	const bearer = {
		id: "bearer",
		method: "client_secret_post",
		secret: "bearer-secret-0123456789abcdef",
	} as const;
	const client: ClientScene = {
		id: bearer.id,
		kind: "confidential",
		method: bearer.method,
		secret: bearer.secret,
		grants: [bearerGrant],
		scopes: ["read"],
		defaultScopes: ["read"],
	};
	const app = await fronted(
		(origin) =>
			oauthScene({
				issuer: origin,
				keys: { signing: signing() },
				clients: [client, agents, jagClient],
				jwtBearer: {
					issuers: [
						{
							issuer: assertionIssuer,
							alg: "ES256",
							publicPem: signer.publicKey.export({ format: "pem", type: "spki" }).toString(),
						},
						{
							issuer: clientlessIssuer,
							alg: "RS256",
							publicPem: agentsSigner.publicKey.export({ format: "pem", type: "spki" }).toString(),
							client: agents.id,
							conditions: { "subject-prefix": "agents/" },
						},
						{
							issuer: idp.issuer,
							alg: "ES256",
							publicPem: idp.publicPem,
							profile: "id-jag",
						},
					],
				},
				// An issuer taking the ID-JAG profile needs DPoP's proofs read.
				dpop: true,
				discovery: true,
			}),
		given,
	).catch(async (failure: unknown) => {
		await idp.stop();
		throw failure;
	});
	return {
		issuer: app.origin,
		ca: app.ca,
		clients: { bearer, agents: { id: agents.id, method: "none" }, jagAgent },
		idp: { issuer: idp.issuer, ca: idp.ca, otherwise: idp.otherwise, issued: idp.issued },
		clientlessIssuer: {
			issuer: clientlessIssuer,
			privateJwk: { ...agentsSigner.privateKey.export({ format: "jwk" }), alg: "RS256" },
			privatePem: agentsSigner.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			subjectPrefix: "agents/",
		},
		assertionIssuer: {
			issuer: assertionIssuer,
			// No kid: the provider holds the issuer's key as a PEM, by no kid, and an assertion naming one would find none.
			privateJwk: { ...signer.privateKey.export({ format: "jwk" }), alg: "ES256" },
		},
		async stop() {
			await app.stop();
			await idp.stop();
		},
	};
}
