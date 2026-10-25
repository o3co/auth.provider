import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type AreaScene, area, areaTarget, onNew, type Started } from "@mod/conformance";
import { codeScene } from "@mod/conformance-code";
import { browserAt } from "@mod/conformance-code/testing";
import { deviceArea } from "@mod/conformance-device";
import { type Front, selfSigned, startFront } from "@mod/conformance-front";
import type { ClientScene } from "@mod/conformance-oauth";

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
		Record<"basic" | "post" | "public" | "assertion" | "device", WorldClient>
	>;
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

/** The address the front tells the app the libraries send from: not loopback, which is its trusted proxy. */
const sender = "198.51.100.30";
const user = { username: "alice", password: "correct horse battery" };
const redirectUri = "https://rp.example/cb";
const resource = "https://api.example";
// The code clients' other audience: what the provider gives where no resource is asked, so asking one shows.
const otherAudience = "https://other-api.example";
const postLogoutRedirectUri = "https://rp.example/logged-out";
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code";
// A secret with the characters RFC 6749 §2.3.1 form-encodes before Basic, where libraries part ways.
const awkward = "s3cret+with%odd:chars and space";

/** What the harness asks of the app beyond the areas' scenes: limits one source's whole run can meet. */
const harnessArea = area<Record<string, never>>("interop-clients");
const perSource = 1000;
// A nonce asked at the token endpoint and at the resources alike, so each library's retry is met (RFC 9449 §8, §9).
const dpopNonce = { required: "as+rs", secret: randomBytes(32).toString("base64") };
onNew(harnessArea, () => ({
	config: {
		dpop: { nonce: dpopNonce },
		authorize: { requests: perSource },
		"token-endpoint": { requests: perSource },
		"token-control": { requests: perSource },
		// The most attempts the login takes in a window.
		"login-password": { attempts: 100, window: "1m" },
	},
}));

const client = (id: string, method: WorldClient["method"], secret?: string): ClientScene => ({
	id,
	kind: method === "none" ? "public" : "confidential",
	method,
	...(secret === undefined ? {} : { secret }),
	grants: ["authorization_code", "refresh_token"],
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

/** An RS256 signing key of this run's own, the algorithm every library takes for an ID token. */
function signing() {
	const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	return {
		kid: `interop-${Date.now().toString(36)}`,
		alg: "RS256" as const,
		privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
		publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
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
 * Starts the front, then the app at the front's origin (by `start`, the conformance target's unless
 * given), its files under `under`; where the app does not start, the front is closed and the files
 * removed before the failure, with what the app told, is thrown.
 */
export async function startWorld(
	given: { readonly start?: (scene: AreaScene) => Promise<Started>; readonly under?: string } = {},
): Promise<World> {
	const start = given.start ?? ((scene: AreaScene) => areaTarget().start(scene));
	const dir = await mkdtemp(join(given.under ?? tmpdir(), "interop-clients-"));
	const tls = await selfSigned("127.0.0.1", dir);
	let base = "";
	const authorizations: URL[] = [];
	const tokenRequests: URLSearchParams[] = [];
	const front: Front = await startFront({
		upstream: () => base,
		publicHost: "127.0.0.1",
		listen: "127.0.0.1",
		tls,
		sender,
		answered: (request) => {
			if (request.method === "POST" && request.url.pathname === "/oauth/token")
				tokenRequests.push(new URLSearchParams(request.body.toString()));
		},
	});
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
	} as const;
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
	const scene = codeScene({
		issuer: front.origin,
		keys: { signing: signing() },
		users: [{ identifier: user.username, password: user.password }],
		clients: [...byCode, byAssertion, byDevice],
		discovery: true,
		userinfo: true,
		refresh: {},
		resourceIndicators: true,
		introspection: true,
		revocation: true,
		dpop: true,
		logout: { allowed: [] },
	});
	const cleared = async () => {
		await front.stop();
		await rm(dir, { recursive: true, force: true });
	};
	const running = await start({
		...scene,
		parts: {
			...scene.parts,
			[deviceArea.name]: { verificationUri: `${front.origin}/device` },
			[harnessArea.name]: {},
		},
	}).catch(async (failure: unknown) => {
		await cleared();
		throw failure;
	});
	if (running.kind !== "running") {
		await cleared();
		throw new Error(`the app refused to start:\n${running.output}`);
	}
	base = running.baseUrl;
	return {
		issuer: front.origin,
		ca: tls.cert,
		clients,
		redirectUri,
		postLogoutRedirectUri,
		resource,
		seen: { authorizations, tokenRequests },
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
		async stop() {
			await running.stop();
			await cleared();
		},
	};
}
