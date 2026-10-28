import { createHash, generateKeyPairSync, type KeyObject, randomUUID, sign } from "node:crypto";
import type { AreaScene } from "@mod/conformance";
import {
	type Deployed,
	type Deploying,
	type Instance,
	type Match,
	on as onDeployment,
	storeWrite,
} from "@mod/conformance/testing";
// The package's entry, which sets the area up on each target.
import { type ClientScene, oauthScene } from "../../main.ts";

export const issuer = "https://issuer.example";
/** The trusted issuer whose assertions the scenes send. */
export const upstream = "https://idp.example";
/** The deployment's `redis.prefix`: the adapter's own, as no scene sets one. */
export const prefix = "store";
export const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const pem = (k: KeyObject, type: "pkcs8" | "spki") => k.export({ format: "pem", type }).toString();
const provider = generateKeyPairSync("ed25519");
const trusted = generateKeyPairSync("ed25519");
export const app: ClientScene = {
	id: "app",
	kind: "confidential",
	method: "client_secret_post",
	secret: "app-secret-0123456789abcdef",
	grants: [grantType],
	scopes: ["read"],
	defaultScopes: ["read"],
};

/** The JWT bearer grant on the Redis store, for one client, trusting one issuer. */
export const faultScene = (): AreaScene =>
	oauthScene({
		issuer,
		keys: {
			signing: {
				kid: "faults",
				alg: "EdDSA",
				privatePem: pem(provider.privateKey, "pkcs8"),
				publicPem: pem(provider.publicKey, "spki"),
			},
		},
		clients: [app],
		jwtBearer: {
			issuers: [{ issuer: upstream, alg: "EdDSA", publicPem: pem(trusted.publicKey, "spki") }],
		},
		storeFaults: true,
	});

/** Runs a scene on a deployment of its own, as the base does, on the OAuth area's scene unless it names another. */
export const on = (
	o: Omit<Deploying, "scene"> & { readonly scene?: AreaScene },
	scene: (d: Deployed) => Promise<void>,
) => onDeployment({ ...o, scene: o.scene ?? faultScene() }, scene);

export interface Assertion {
	readonly jwt: string;
	readonly jti: string;
}

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
/** An assertion the trusted issuer signs for alice, with a `jti` of its own. */
export function assertion(): Assertion {
	const now = Math.floor(Date.now() / 1000);
	const jti = randomUUID();
	const body = { iss: upstream, sub: "alice", aud: issuer, iat: now, exp: now + 300, jti };
	const input = `${b64({ alg: "EdDSA", typ: "JWT" })}.${b64(body)}`;
	return {
		jwt: `${input}.${sign(null, Buffer.from(input), trusted.privateKey).toString("base64url")}`,
		jti,
	};
}

/** A token endpoint's answer: its status and JSON body. */
export interface Answer {
	readonly status: number;
	readonly body: Readonly<Record<string, unknown>>;
}

/** The assertion sent to the instance's token endpoint by `app`. */
export async function grantAt(i: Instance, a: Assertion): Promise<Answer> {
	const res = await fetch(`${i.baseUrl}/oauth/token`, {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: grantType,
			assertion: a.jwt,
			client_id: app.id,
			client_secret: app.secret ?? "",
		}),
	});
	const text = await res.text();
	let body: Record<string, unknown> = {};
	try {
		body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
	} catch {}
	return { status: res.status, body };
}

/** An answer as a scene compares it: its status and error, or its token type where it gave a token. */
export const said = (a: Answer) => [a.status, a.body.error ?? a.body.token_type];

/** The write that spends the assertion's `jti`: its record placed under the issuer's and the jti's name. */
export const spendOf = (a: Assertion): Match =>
	storeWrite({
		prefix,
		space: "jwt-bearer-store.spent",
		partition: createHash("sha256")
			.update(JSON.stringify([upstream, a.jti]))
			.digest("base64url"),
		operations: ["putIfAbsent"],
	});

const clientKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
/** The client that authenticates by an assertion signed with its key (`private_key_jwt`). */
export const keyed: ClientScene = {
	id: "keyed",
	kind: "confidential",
	method: "private_key_jwt",
	keys: [{ ...clientKey.publicKey.export({ format: "jwk" }), kid: "k1", use: "sig" }],
	grants: ["client_credentials"],
	scopes: ["read"],
	defaultScopes: ["read"],
};

/** Client credentials on the Redis store, for one client authenticating by its key. */
export const keyedScene = (): AreaScene =>
	oauthScene({
		issuer,
		keys: {
			signing: {
				kid: "faults",
				alg: "EdDSA",
				privatePem: pem(provider.privateKey, "pkcs8"),
				publicPem: pem(provider.publicKey, "spki"),
			},
		},
		clients: [keyed],
		storeFaults: true,
	});

/** An assertion the keyed client signs to authenticate, with a `jti` of its own. */
export function clientAssertion(): Assertion {
	const now = Math.floor(Date.now() / 1000);
	const jti = randomUUID();
	const body = { iss: keyed.id, sub: keyed.id, aud: issuer, iat: now, exp: now + 300, jti };
	const input = `${b64({ alg: "ES256", kid: "k1" })}.${b64(body)}`;
	const signature = sign("sha256", Buffer.from(input), {
		key: clientKey.privateKey,
		dsaEncoding: "ieee-p1363",
	}).toString("base64url");
	return { jwt: `${input}.${signature}`, jti };
}

/** A client credentials request the keyed client authenticates by the assertion. */
export async function authenticatedAt(i: Instance, a: Assertion): Promise<Answer> {
	const res = await fetch(`${i.baseUrl}/oauth/token`, {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "client_credentials",
			client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			client_assertion: a.jwt,
		}),
	});
	const text = await res.text();
	let body: Record<string, unknown> = {};
	try {
		body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
	} catch {}
	return { status: res.status, body };
}

/** The write that spends the client assertion's `jti`: its record placed under the client's and the jti's name. */
export const clientSpendOf = (a: Assertion): Match =>
	storeWrite({
		prefix,
		space: "client-assertion-store.spent",
		partition: createHash("sha256")
			.update(JSON.stringify([keyed.id, a.jti]))
			.digest("base64url"),
		operations: ["putIfAbsent"],
	});
