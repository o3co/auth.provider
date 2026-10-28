import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import type { AreaScene } from "@mod/conformance";
import {
	type Instance,
	type Match,
	startDeployment,
	startTopology,
	storeWrite,
	type Topology,
} from "@mod/conformance/testing";
import type { ClientScene } from "@mod/conformance-oauth";
// The package's entry, which sets the area up on each target.
import { type CodeScene, codeScene } from "../../main.ts";
import { backChannel, browserAt } from "../../testing.ts";

export const issuer = "https://issuer.example";
export const callback = "https://app.example/cb";
/** The deployment's `redis.prefix`: the adapter's own, as no scene sets one. */
export const prefix = "store";
const pair = generateKeyPairSync("ed25519");
const alice = { username: "alice", password: "alice-horse-battery-staple" };
export const app: ClientScene = {
	id: "app",
	kind: "confidential",
	method: "client_secret_post",
	secret: "app-secret-0123456789abcdef",
	grants: ["authorization_code", "refresh_token"],
	scopes: ["openid"],
	defaultScopes: ["openid"],
	redirectUris: [callback],
	firstParty: true,
};

/** The code flow on the Redis store, one client and one user, with what a scene adds. */
export const faultScene = (more: Partial<CodeScene> = {}): AreaScene =>
	codeScene({
		issuer,
		keys: {
			signing: {
				kid: "faults",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		// The refresh grant only where refresh is composed, which boot otherwise refuses.
		clients: [more.refresh ? app : { ...app, grants: ["authorization_code"] }],
		users: [{ identifier: alice.username, password: alice.password }],
		...more,
		storeFaults: true,
	});

/** What every node of a topology with replicas starts with: a write needs one replica, lagging no more than 2 s. */
const replicated = ["--min-replicas-to-write", "1", "--min-replicas-max-lag", "2"];

export interface Deployed {
	readonly topology: Topology;
	readonly instances: readonly Instance[];
	stop(): Promise<void>;
}

/** A scene deployed on a topology of its own: 2 replicas and 1 instance unless said otherwise. */
export async function deployed(o: {
	readonly name: string;
	readonly scene?: AreaScene;
	readonly replicas?: number;
	readonly instances?: number;
	/** Settings every node starts with, after the replication's. */
	readonly settings?: readonly string[];
	/** Keys of the Redis section beside its URL. */
	readonly redis?: Readonly<Record<string, unknown>>;
}): Promise<Deployed> {
	const replicas = o.replicas ?? 2;
	const topology = await startTopology({
		replicas,
		settings: [...(replicas > 0 ? replicated : []), ...(o.settings ?? [])],
	});
	try {
		const deployment = await startDeployment({
			name: o.name,
			scene: o.scene ?? faultScene(),
			topology,
			instances: o.instances ?? 1,
			...(o.redis ? { redis: o.redis } : {}),
		});
		return {
			topology,
			instances: deployment.instances,
			async stop() {
				try {
					await deployment.stop();
				} finally {
					await topology.stop();
				}
			},
		};
	} catch (error) {
		await topology.stop();
		throw error;
	}
}

/** Runs a scene on a deployment of its own, stopped however the scene ends. */
export async function on(o: Parameters<typeof deployed>[0], scene: (d: Deployed) => Promise<void>) {
	const d = await deployed(o);
	try {
		await scene(d);
	} finally {
		await d.stop();
	}
}

/** The instance at `index`, which the scene's deployment must have. */
export const instanceOf = (d: Deployed, index = 0): Instance => {
	const i = d.instances[index];
	if (!i) throw new Error(`the deployment has no instance ${index}`);
	return i;
};

/** A verifier of its own, so a scene tells its code's writes from any other by the challenge. */
export function pkce() {
	const verifier = randomBytes(32).toString("base64url");
	return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

export interface Code {
	readonly code: string;
	readonly verifier: string;
	readonly challenge: string;
}

/** A browser behind the instance's proxy that logs in there. */
export const browserOn = (i: Instance) => browserAt(() => i.baseUrl, issuer, alice);

/** A code the instance gives a browser logged in at it (a new one unless given), for `app`. */
export async function codeAt(i: Instance, browser = browserOn(i)): Promise<Code> {
	const { verifier, challenge } = pkce();
	const res = await browser.authorize({
		response_type: "code",
		client_id: app.id,
		redirect_uri: callback,
		state: "s1",
		scope: "openid",
		code_challenge: challenge,
		code_challenge_method: "S256",
	});
	const code = res.at?.searchParams.get("code");
	if (!code) throw new Error(`the authorization endpoint gave no code: ${res.status}`);
	return { code, verifier, challenge };
}

/** A token endpoint's answer: its status and JSON body, or none where the instance cut it short. */
export interface Answer {
	readonly status: number;
	readonly body: Readonly<Record<string, unknown>>;
}

/** A request to the instance's token endpoint as `app`. */
export async function tokenAt(
	i: Instance,
	form: Readonly<Record<string, string>>,
): Promise<Answer> {
	const res = await fetch(`${i.baseUrl}/oauth/token`, {
		method: "POST",
		headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ ...form, client_id: app.id, client_secret: app.secret ?? "" }),
	});
	const text = await res.text();
	let body: Record<string, unknown> = {};
	try {
		body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
	} catch {}
	return { status: res.status, body };
}

export const redeemAt = (i: Instance, c: Code) =>
	tokenAt(i, {
		grant_type: "authorization_code",
		code: c.code,
		redirect_uri: callback,
		code_verifier: c.verifier,
	});

/** An answer as a scene compares it: its status and error, or its token type where it gave a token. */
export const said = (a: Answer) => [a.status, a.body.error ?? a.body.token_type];

export const refreshAt = (i: Instance, token: string) =>
	tokenAt(i, { grant_type: "refresh_token", refresh_token: token });

/** A refresh token's family, which names its record, and its secret. */
const partsOf = (token: string) => {
	const [family = "", secret = ""] = token.split(".");
	return { family, secret };
};

/**
 * The write that rotates a family from `token`: its record's current secret moved off the token's,
 * the family still live; a revocation, which keeps no current secret, is none.
 */
export function rotationFrom(token: string): Match {
	const { family, secret } = partsOf(token);
	const presented = createHash("sha256").update(secret).digest("base64url");
	return storeWrite({
		prefix,
		space: "refresh-store.families",
		partition: family,
		operations: ["replaceIf"],
		value: (v) => {
			const current = (v as { current?: unknown }).current;
			return typeof current === "string" && current !== presented;
		},
	});
}

/** A code's record as the store holds it: the fields a scene tells its writes by. */
interface CodeRecord {
	readonly state?: unknown;
	readonly challenge?: unknown;
	readonly token?: unknown;
	readonly void?: unknown;
}
const codeWrite = (challenge: string, is: (r: CodeRecord) => boolean): Match =>
	storeWrite({
		prefix,
		space: "code-grant-store.codes",
		operations: ["replaceIf"],
		value: (v) => (v as CodeRecord).challenge === challenge && is(v as CodeRecord),
	});

/** The write that uses the code up: its record turned consumed, before any token is noted on it. */
export const codeUse = (c: Code) =>
	codeWrite(c.challenge, (r) => r.state === "consumed" && r.token === undefined && !r.void);

/** The write that notes, on the used code, the token issued for it. */
export const codeNoted = (c: Code) =>
	codeWrite(c.challenge, (r) => r.state === "consumed" && r.token !== undefined && !r.void);

/** The successful executions the relay saw of a match. */
export const successes = (i: Instance, match: Match) =>
	i.relay.executions(match).filter((e) => e.succeeded);

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Until the instance's relay holds an open connection to `upstream`, within 10 s. */
export async function reconnected(i: Instance, upstream: { host: string; port: number }) {
	const end = performance.now() + 10_000;
	const to = (c: { upstream: { host: string; port: number } }) =>
		c.upstream.host === upstream.host && c.upstream.port === upstream.port;
	while (!i.relay.connections().some((c) => c.open && to(c))) {
		if (performance.now() > end) throw new Error(`instance ${i.index} did not connect again`);
		await pause(100);
	}
}

/** Until the instance answers `/readyz` ready, within 30 s, as a scene waits for a fault healed. */
export async function ready(i: Instance, ms = 30_000): Promise<void> {
	const end = performance.now() + ms;
	for (;;) {
		const status = await fetch(`${i.baseUrl}/readyz`, { headers: backChannel }).then(
			(r) => r.status,
			() => 0,
		);
		if (status === 200) return;
		if (performance.now() > end) throw new Error(`instance ${i.index} not ready within ${ms} ms`);
		await pause(200);
	}
}

/**
 * Promotes a replica that has caught up, as `promotion` checks, killing the old primary and
 * reattaching the other replicas, then points every instance's relay at the new primary.
 */
export async function failover(d: Deployed): Promise<void> {
	const [next, ...others] = d.topology.replicas();
	if (!next) throw new Error("no replica to promote");
	await d.topology.promote({ replica: next, reattach: others });
	repointed(d);
	await replicasOnline(d);
}

/**
 * Until the primary has every replica the topology names online again, within 30 s: a node started
 * again answers before its replicas are back, and a write needs one of them.
 */
export async function replicasOnline(d: Deployed): Promise<void> {
	const end = performance.now() + 30_000;
	const want = d.topology.replicas().length;
	for (;;) {
		const info = await d.topology.primary().ask("INFO", "replication");
		const text = info.kind === "bulk" ? (info.data?.toString() ?? "") : "";
		const online = text.split("\n").filter((l) => /^slave\d+:.*state=online/.test(l)).length;
		if (online >= want) return;
		if (performance.now() > end) throw new Error(`${online} of ${want} replicas online`);
		await pause(100);
	}
}

/** Points every instance's relay at the primary where it answers now, as a crash may move it. */
export function repointed(d: Deployed): void {
	for (const i of d.instances) {
		i.relay.switchUpstream(d.topology.primary().upstream());
		i.relay.reset("all");
	}
}
