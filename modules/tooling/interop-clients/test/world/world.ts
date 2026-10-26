import { generateKeyPairSync, X509Certificate } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type AreaScene, freePort, type Started } from "@mod/conformance";
import { codeScene } from "@mod/conformance-code";
import { browserAt } from "@mod/conformance-code/testing";
import { deviceArea } from "@mod/conformance-device";
import { exchangeArea } from "@mod/conformance-exchange";
import { selfSigned } from "@mod/conformance-front";
import type { ClientScene } from "@mod/conformance-oauth";
import { fronted, sender, signing } from "./fronted.ts";

/** A client the world registers, as an adapter is told of it. */
export interface WorldClient {
	readonly id: string;
	readonly method: "client_secret_basic" | "client_secret_post" | "none" | "private_key_jwt";
	readonly secret?: string;
	/** Its private key, as a JWK with its `kid` and `alg`, under `private_key_jwt`. */
	readonly privateJwk?: Readonly<Record<string, unknown>>;
}

/** The provider the libraries meet, behind its https front, and what the driver does as the browser. */
export interface World {
	/** The provider's issuer: the front's origin. */
	readonly issuer: string;
	/** The front's certificate, as PEM, which every adapter trusts and nothing else. */
	readonly ca: string;
	readonly clients: Readonly<
		Record<
			| "basic"
			| "post"
			| "public"
			| "assertion"
			| "device"
			| "mtls"
			| "backchannel"
			| "service"
			| "publicDevice",
			WorldClient
		>
	>;
	/** The `mtls` client's certificate and key, as PEM, and its thumbprint (`x5t#S256`). */
	readonly clientCertificate: {
		readonly cert: string;
		readonly key: string;
		readonly thumbprint: string;
	};
	/** Where the `backchannel` client is told a session ended: the port and path its receiver listens at. */
	readonly backchannel: { readonly port: number; readonly path: string };
	readonly redirectUri: string;
	/** Where a logout the code clients start may send the browser back. */
	readonly postLogoutRedirectUri: string;
	/** The resource server a client may ask its token for (RFC 8707). */
	readonly resource: string;
	/** What the provider's introspection answers of a token, asked as the `post` client. */
	introspect(token: string): Promise<Record<string, unknown>>;
	/** Each authorization URL a library sent the browser to, and each token request it sent through the front, in order. */
	readonly seen: {
		readonly authorizations: readonly URL[];
		readonly tokenRequests: readonly URLSearchParams[];
	};
	/**
	 * A browser with its own session: it logs in and follows an authorization URL to the redirect,
	 * approves a device's user code, and follows an end-session URL to where the logout sends it.
	 */
	browser(): {
		authorize(url: string): Promise<string>;
		approve(userCode: string): Promise<void>;
		endSession(url: string): Promise<string>;
	};
	stop(): Promise<void>;
}

const user = { username: "alice", password: "correct horse battery" };
const redirectUri = "https://rp.example/cb";
const resource = "https://api.example";
// The code clients' other audience: what the provider gives where no resource is asked, so asking one shows.
const otherAudience = "https://other-api.example";
const postLogoutRedirectUri = "https://rp.example/logged-out";
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code";
const exchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
const certificateHeader = "x-client-certificate";
// A secret with the characters RFC 6749 §2.3.1 form-encodes before Basic, where libraries part ways.
const awkward = "s3cret+with%odd:chars and space";

const client = (id: string, method: WorldClient["method"], secret?: string): ClientScene => ({
	id,
	kind: method === "none" ? "public" : "confidential",
	method,
	...(secret === undefined ? {} : { secret }),
	grants: ["authorization_code", "refresh_token", exchangeGrant],
	scopes: ["openid", "profile", "email", "offline_access"],
	audiences: [otherAudience, resource],
	redirectUris: [redirectUri],
	firstParty: true,
	logout: { postLogoutRedirectUris: [postLogoutRedirectUri] },
});

/** An ES256 key of this run's own for the client that authenticates by its assertions. */
function assertionKey() {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const kid = `assertion-${Date.now().toString(36)}`;
	return {
		privateJwk: { ...privateKey.export({ format: "jwk" }), kid, alg: "ES256" },
		publicJwk: { ...publicKey.export({ format: "jwk" }), kid, alg: "ES256", use: "sig" },
	};
}

/** The query of an authorization URL a library built, where it is the provider's authorization endpoint at its issuer. */
export function authorizationQuery(url: string, issuer: string): string {
	const at = new URL(url);
	// Followed as given, not mended: a discovery that told another endpoint fails here.
	if (at.origin !== new URL(issuer).origin || at.pathname !== "/oauth/authorize")
		throw new Error(
			`the library sent the browser to ${at.origin}${at.pathname}, not the provider's authorization endpoint`,
		);
	return at.search.slice(1);
}

/**
 * Starts the provider the code flows meet, behind its front (`fronted`): code, public, assertion and
 * device clients, one user, DPoP, a logout the client starts, the device grant and token exchange.
 */
export async function startWorld(
	given: { readonly start?: (scene: AreaScene) => Promise<Started>; readonly under?: string } = {},
): Promise<World> {
	const authorizations: URL[] = [];
	// The client certificate's files are read back as PEM and gone before anything else starts.
	const certificateDir = await mkdtemp(join(given.under ?? tmpdir(), "interop-client-cert-"));
	const certificate = await selfSigned("client.example", certificateDir).finally(() =>
		rm(certificateDir, { recursive: true, force: true }),
	);
	const thumbprint = Buffer.from(
		await crypto.subtle.digest("SHA-256", new X509Certificate(certificate.cert).raw),
	).toString("base64url");
	const backchannel = { port: await freePort(), path: "/backchannel" };
	const receiver = `http://127.0.0.1:${backchannel.port}`;
	const key = assertionKey();
	const clients = {
		basic: { id: "basic", method: "client_secret_basic", secret: awkward },
		post: { id: "post", method: "client_secret_post", secret: "post-secret-0123456789abcdef" },
		public: { id: "public", method: "none" },
		assertion: { id: "assertion", method: "private_key_jwt", privateJwk: key.privateJwk },
		device: {
			id: "device",
			method: "client_secret_post",
			secret: "device-secret-0123456789abcdef",
		},
		mtls: { id: "mtls", method: "client_secret_post", secret: "mtls-secret-0123456789abcdef" },
		service: {
			id: "service",
			method: "client_secret_basic",
			secret: "service-secret-0123456789abcdef",
		},
		publicDevice: { id: "public-device", method: "none" },
		backchannel: {
			id: "backchannel",
			method: "client_secret_basic",
			secret: "backchannel-secret-0123456789abcdef",
		},
	} as const;
	const byMtls: ClientScene = {
		id: clients.mtls.id,
		kind: "confidential",
		method: "client_secret_post",
		secret: clients.mtls.secret,
		grants: ["client_credentials"],
		scopes: ["read"],
		defaultScopes: ["read"],
		audiences: [resource],
	};
	const byService: ClientScene = {
		...byMtls,
		id: clients.service.id,
		method: "client_secret_basic",
		secret: clients.service.secret,
	};
	const byBackchannel: ClientScene = {
		...client(clients.backchannel.id, clients.backchannel.method, clients.backchannel.secret),
		logout: {
			postLogoutRedirectUris: [postLogoutRedirectUri],
			backchannelLogoutUri: `${receiver}${backchannel.path}`,
			backchannelLogoutSessionRequired: true,
		},
	};
	const byCode = [clients.basic, clients.post, clients.public].map((c) =>
		client(c.id, c.method, "secret" in c ? c.secret : undefined),
	);
	const byAssertion: ClientScene = {
		id: clients.assertion.id,
		kind: "confidential",
		method: "private_key_jwt",
		keys: [key.publicJwk],
		grants: ["client_credentials"],
		scopes: ["read"],
		defaultScopes: ["read"],
		audiences: [resource],
	};
	const byDevice: ClientScene = {
		id: clients.device.id,
		kind: "confidential",
		method: "client_secret_post",
		secret: clients.device.secret,
		grants: [deviceGrant],
		scopes: ["openid", "read"],
		// The audience the harness's introspecting client may see too.
		audiences: [resource],
	};
	// The device grant's own case (RFC 8628 §3.1): a public client, which names itself alone.
	const { secret: _, ...deviceAllowance } = byDevice;
	const byPublicDevice: ClientScene = {
		...deviceAllowance,
		id: clients.publicDevice.id,
		kind: "public",
		method: "none",
	};
	const app = await fronted(
		(origin) => {
			const scene = codeScene({
				issuer: origin,
				keys: { signing: signing() },
				users: [{ identifier: user.username, password: user.password }],
				clients: [
					...byCode,
					byAssertion,
					byDevice,
					byMtls,
					byService,
					byPublicDevice,
					byBackchannel,
				],
				discovery: true,
				userinfo: true,
				refresh: {},
				resourceIndicators: true,
				introspection: true,
				revocation: true,
				dpop: true,
				// Only the back-channel receiver's origin is reached, over plain http at loopback.
				logout: { allowed: [receiver] },
				// Any certificate the front forwards binds; the front is the one proxy, at loopback.
				mtls: {
					header: { dialect: "pem", name: certificateHeader },
					trustedProxies: ["127.0.0.1"],
				},
			});
			return {
				...scene,
				parts: {
					...scene.parts,
					[exchangeArea.name]: {},
					[deviceArea.name]: { verificationUri: `${origin}/device` },
				},
			};
		},
		{ ...given, clientCertificateHeader: certificateHeader },
	);
	const base = app.base();
	const front = { origin: app.origin };
	return {
		issuer: front.origin,
		ca: app.ca,
		clients,
		redirectUri,
		postLogoutRedirectUri,
		clientCertificate: { cert: certificate.cert, key: certificate.key, thumbprint },
		backchannel,
		resource,
		seen: { authorizations, tokenRequests: app.tokenRequests },
		async introspect(token: string) {
			const answer = await fetch(`${base}/oauth/introspect`, {
				method: "POST",
				headers: {
					"content-type": "application/x-www-form-urlencoded",
					"x-forwarded-proto": "https",
					"x-forwarded-for": sender,
				},
				body: new URLSearchParams({
					token,
					client_id: clients.post.id,
					client_secret: clients.post.secret,
				}),
			});
			if (!answer.ok)
				throw new Error(
					`introspection answered ${answer.status}: ${(await answer.text()).slice(0, 200)}`,
				);
			return (await answer.json()) as Record<string, unknown>;
		},
		browser() {
			const at = browserAt(() => base, front.origin, user);
			return {
				async authorize(url: string) {
					authorizations.push(new URL(url));
					const answer = await at.authorize(authorizationQuery(url, front.origin));
					if (!answer.at)
						throw new Error(
							`the authorization endpoint answered ${answer.status}: ${answer.text.slice(0, 300)}`,
						);
					return answer.at.href;
				},
				async approve(userCode: string) {
					// The deployment's page posts the user's decision as JSON, the session's cookie with it.
					const answer = await fetch(`${base}/oauth/device/verification`, {
						method: "POST",
						headers: at.headers({
							"content-type": "application/json",
							origin: front.origin,
							cookie: await at.login(),
						}),
						body: JSON.stringify({ action: "approve", user_code: userCode }),
					});
					if (!answer.ok)
						throw new Error(
							`the device's approval answered ${answer.status}: ${(await answer.text()).slice(0, 200)}`,
						);
				},
				async endSession(url: string) {
					const asked = new URL(url);
					if (asked.origin !== front.origin || asked.pathname !== "/oauth/logout")
						throw new Error(
							`the library sent the browser to ${asked.origin}${asked.pathname}, not the provider's end-session endpoint`,
						);
					const answer = await fetch(`${base}/oauth/logout${asked.search}`, {
						redirect: "manual",
						headers: at.headers({ cookie: await at.login() }),
					});
					const location = answer.headers.get("location");
					if (!location)
						throw new Error(
							`the end-session endpoint answered ${answer.status}: ${(await answer.text()).slice(0, 200)}`,
						);
					return location;
				},
			};
		},
		stop: () => app.stop(),
	};
}
