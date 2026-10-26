import { generateKeyPairSync } from "node:crypto";
import type { AreaScene, Started } from "@mod/conformance";
import { type ClientScene, oauthScene } from "@mod/conformance-oauth";
import { fronted, signing } from "./fronted.ts";
import type { WorldClient } from "./world.ts";

/** The provider services meet (the `a2a` pattern's app): no user, session or login. */
export interface ServicesWorld {
	readonly issuer: string;
	readonly ca: string;
	readonly clients: Readonly<Record<"bearer", WorldClient>>;
	/** The issuer whose JWT assertions the jwt-bearer grant trusts, with its private key as a JWK. */
	readonly assertionIssuer: {
		readonly issuer: string;
		readonly privateJwk: Readonly<Record<string, unknown>>;
	};
	stop(): Promise<void>;
}

const bearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const assertionIssuer = "https://assertions.example";

/**
 * Starts the provider services meet, behind its front: a client allowed the jwt-bearer grant, and
 * an issuer whose assertions it trusts. A grant without a session has no source to vouch for a
 * user's email, so it is no grant of the full template's app, whose users are a ledger's.
 */
export async function startServicesWorld(
	given: { readonly start?: (scene: AreaScene) => Promise<Started>; readonly under?: string } = {},
): Promise<ServicesWorld> {
	const signer = generateKeyPairSync("ec", { namedCurve: "P-256" });
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
				clients: [client],
				jwtBearer: {
					issuers: [
						{
							issuer: assertionIssuer,
							alg: "ES256",
							publicPem: signer.publicKey.export({ format: "pem", type: "spki" }).toString(),
						},
					],
				},
				discovery: true,
			}),
		given,
	);
	return {
		issuer: app.origin,
		ca: app.ca,
		clients: { bearer },
		assertionIssuer: {
			issuer: assertionIssuer,
			// No kid: the provider holds the issuer's key as a PEM, by no kid, and an assertion naming one would find none.
			privateJwk: { ...signer.privateKey.export({ format: "jwk" }), alg: "ES256" },
		},
		stop: () => app.stop(),
	};
}
