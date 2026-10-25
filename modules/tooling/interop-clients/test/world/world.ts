import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type AreaScene, area, areaTarget, onNew, type Started } from "@mod/conformance";
import { codeScene } from "@mod/conformance-code";
import { browserAt } from "@mod/conformance-code/testing";
import { type Front, selfSigned, startFront } from "@mod/conformance-front";
import type { ClientScene } from "@mod/conformance-oauth";

/** A client the world registers, as an adapter is told of it. */
export interface WorldClient {
	readonly id: string;
	readonly method: "client_secret_basic" | "client_secret_post" | "none";
	readonly secret?: string;
}

/** The provider the libraries meet, behind its https front, and what the driver does as the browser. */
export interface World {
	/** The provider's issuer: the front's origin. */
	readonly issuer: string;
	/** The front's certificate, as PEM, which every adapter trusts and nothing else. */
	readonly ca: string;
	readonly clients: Readonly<Record<"basic" | "post" | "public", WorldClient>>;
	readonly redirectUri: string;
	/** A browser with its own session: it logs in and follows an authorization URL to the redirect. */
	browser(): { authorize(url: string): Promise<string> };
	stop(): Promise<void>;
}

/** The address the front tells the app the libraries send from: not loopback, which is its trusted proxy. */
const sender = "198.51.100.30";
const user = { username: "alice", password: "correct horse battery" };
const redirectUri = "https://rp.example/cb";
// A secret with the characters RFC 6749 §2.3.1 form-encodes before Basic, where libraries part ways.
const awkward = "s3cret+with%odd:chars and space";

/** What the harness asks of the app beyond the areas' scenes: limits one source's whole run can meet. */
const harnessArea = area<Record<string, never>>("interop-clients");
const perSource = 1000;
onNew(harnessArea, () => ({
	config: {
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
	redirectUris: [redirectUri],
	firstParty: true,
});

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
	const front: Front = await startFront({
		upstream: () => base,
		publicHost: "127.0.0.1",
		listen: "127.0.0.1",
		tls,
		sender,
	});
	const clients = {
		basic: { id: "basic", method: "client_secret_basic", secret: awkward },
		post: { id: "post", method: "client_secret_post", secret: "post-secret-0123456789abcdef" },
		public: { id: "public", method: "none" },
	} as const;
	const scene = codeScene({
		issuer: front.origin,
		keys: { signing: signing() },
		users: [{ identifier: user.username, password: user.password }],
		clients: Object.values(clients).map((c) =>
			client(c.id, c.method, "secret" in c ? c.secret : undefined),
		),
		discovery: true,
		userinfo: true,
		refresh: {},
	});
	const cleared = async () => {
		await front.stop();
		await rm(dir, { recursive: true, force: true });
	};
	const running = await start({
		...scene,
		parts: { ...scene.parts, [harnessArea.name]: {} },
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
		browser() {
			const at = browserAt(() => base, front.origin, user);
			return {
				async authorize(url: string) {
					const answer = await at.authorize(authorizationQuery(url, front.origin));
					if (!answer.at)
						throw new Error(
							`the authorization endpoint answered ${answer.status}: ${answer.text.slice(0, 300)}`,
						);
					return answer.at.href;
				},
			};
		},
		async stop() {
			await running.stop();
			await cleared();
		},
	};
}
