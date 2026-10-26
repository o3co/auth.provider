import { constants, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { oauthScene } from "../../main.ts";

const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const issuer = "https://issuer.example";
/** One key signing the subjects of two organisations: its entry names the one this server takes. */
const shared = "https://ci.example";
const narrowed = "https://narrow.example";
const pss = "https://pss.example";
const pem = (k: KeyObject, type: "pkcs8" | "spki") => k.export({ format: "pem", type }).toString();
const provider = generateKeyPairSync("ed25519");
const sharedKey = generateKeyPairSync("ed25519");
const narrowKey = generateKeyPairSync("ed25519");
const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const secret = "app-secret-0123456789abcdef";

const scene = oauthScene({
	issuer,
	keys: {
		signing: {
			kid: "jb",
			alg: "EdDSA",
			privatePem: pem(provider.privateKey, "pkcs8"),
			publicPem: pem(provider.publicKey, "spki"),
		},
	},
	clients: [
		{
			id: "app",
			kind: "confidential",
			method: "client_secret_post",
			secret,
			grants: [grantType],
			scopes: ["read", "write"],
			defaultScopes: ["read", "write"],
		},
	],
	jwtBearer: {
		issuers: [
			{
				issuer: shared,
				alg: "EdDSA",
				publicPem: pem(sharedKey.publicKey, "spki"),
				conditions: { "subject-prefix": "org:acme/" },
			},
			{
				issuer: narrowed,
				alg: "EdDSA",
				publicPem: pem(narrowKey.publicKey, "spki"),
				ceiling: { scopes: ["read"] },
			},
			{ issuer: pss, alg: "PS256", publicPem: pem(rsa.publicKey, "spki") },
		],
	},
});

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
/** An assertion `iss` signs with `alg`, for the subject and claims given. */
function assertion(iss: string, alg: "EdDSA" | "PS256" | "RS256", claims: Record<string, unknown>) {
	const now = Math.floor(Date.now() / 1000);
	const body = { iss, aud: issuer, iat: now, exp: now + 120, jti: `j-${Math.random()}`, ...claims };
	const signed = `${b64({ alg, typ: "JWT" })}.${b64(body)}`;
	const input = Buffer.from(signed);
	const signature =
		alg === "EdDSA"
			? sign(null, input, iss === shared ? sharedKey.privateKey : narrowKey.privateKey)
			: alg === "PS256"
				? sign("sha256", input, {
						key: rsa.privateKey,
						padding: constants.RSA_PKCS1_PSS_PADDING,
						saltLength: 32,
					})
				: sign("sha256", input, rsa.privateKey);
	return `${signed}.${signature.toString("base64url")}`;
}

async function post(base: string, form: Record<string, string>) {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ client_id: "app", client_secret: secret, ...form }),
	});
	return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe.runIf(areaTarget().can("trusted-issuers"))("C. jwt-bearer: each issuer's policy", () => {
	let base = "";
	let running: Started;
	beforeAll(async () => {
		running = await areaTarget().start(scene);
		if (running.kind !== "running") throw new Error(running.output);
		base = running.baseUrl;
	});
	afterAll(async () => {
		if (running?.kind === "running") await running.stop();
	});
	const grant = (a: string, more: Record<string, string> = {}) =>
		post(base, { grant_type: grantType, assertion: a, ...more });

	it("takes, of an issuer two organisations share, only the assertions its conditions name, the others' jti left unused", async () => {
		const jti = `j-${Math.random()}`;
		const theirs = await grant(assertion(shared, "EdDSA", { sub: "org:other/ci", jti }));
		expect([theirs.status, theirs.body.error]).toEqual([400, "invalid_grant"]);
		const ours = await grant(assertion(shared, "EdDSA", { sub: "org:acme/ci", jti }));
		expect(ours.status).toBe(200);
		expect(ours.body.scope).toBe("read write");
	});

	it("issues an issuer's token within its ceiling as well as the client's allowance", async () => {
		const narrow = await grant(assertion(narrowed, "EdDSA", { sub: "alice" }));
		expect([narrow.status, narrow.body.scope]).toEqual([200, "read"]);
		const asked = await grant(assertion(narrowed, "EdDSA", { sub: "alice" }), { scope: "write" });
		expect([asked.status, asked.body.error]).toEqual([400, "invalid_scope"]);
	});

	it("takes an issuer's PS256 assertion with its key written for PS256, and not one that key signs with RS256", async () => {
		expect((await grant(assertion(pss, "PS256", { sub: "alice" }))).status).toBe(200);
		const other = await grant(assertion(pss, "RS256", { sub: "alice" }));
		expect([other.status, other.body.error]).toEqual([400, "invalid_grant"]);
	});
});
