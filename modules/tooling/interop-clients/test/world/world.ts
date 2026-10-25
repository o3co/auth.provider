import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { area, areaTarget, onNew, type Started } from "@mod/conformance";
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
	/** The front's certificate, which every adapter trusts and nothing else; as PEM, and in a file. */
	readonly ca: string;
	readonly caFile: string;
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

/** Starts the front, then the app at the front's origin; a refused start fails with what the app told. */
export async function startWorld(): Promise<World> {
	const dir = await mkdtemp(join(tmpdir(), "interop-clients-"));
	const tls = await selfSigned("127.0.0.1", dir);
	const caFile = join(dir, "ca.pem");
	await writeFile(caFile, tls.cert);
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
	const running: Started = await areaTarget().start({
		...scene,
		parts: { ...scene.parts, [harnessArea.name]: {} },
	});
	if (running.kind !== "running") {
		await front.stop();
		throw new Error(`the app refused to start:\n${running.output}`);
	}
	base = running.baseUrl;
	return {
		issuer: front.origin,
		ca: tls.cert,
		caFile,
		clients,
		redirectUri,
		browser() {
			const at = browserAt(() => base, front.origin, user);
			return {
				async authorize(url: string) {
					const answer = await at.authorize(new URL(url).search.slice(1));
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
			await front.stop();
			await rm(dir, { recursive: true, force: true });
		},
	};
}
