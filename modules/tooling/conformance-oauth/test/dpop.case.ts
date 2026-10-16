import { generateKeyPairSync, randomUUID } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { calculateJwkThumbprint, exportJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { oauthScene } from "../src/main.ts";

const issuer = "https://issuer.example";
const signing = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");
const secret = "app-secret-0123456789abcdef";
const scene = (dpop: boolean) =>
	oauthScene({
		issuer,
		keys: {
			signing: {
				kid: "dp",
				alg: "EdDSA",
				privatePem: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: signing.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		clients: [
			{
				id: "app",
				kind: "confidential",
				method: "client_secret_post",
				secret,
				grants: ["client_credentials"],
				scopes: ["read"],
				defaultScopes: ["read"],
				audiences: ["https://api.example"],
			},
		],
		introspection: true,
		dpop,
	});

async function proof(claims: Record<string, unknown> = {}) {
	return new SignJWT({
		htm: "POST",
		htu: `${issuer}/oauth/token`,
		iat: Math.floor(Date.now() / 1000),
		jti: randomUUID(),
		...claims,
	})
		.setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt", jwk: await exportJWK(holder.publicKey) })
		.sign(holder.privateKey);
}
const claimsOf = (jwt: unknown) =>
	JSON.parse(Buffer.from(String(jwt).split(".")[1] ?? "", "base64url").toString()) as Record<
		string,
		unknown
	>;

function running(dpop: boolean) {
	let started: Started;
	const s = { base: "" };
	beforeAll(async () => {
		started = await areaTarget().start(scene(dpop));
		if (started.kind !== "running") throw new Error(`refused:\n${started.output}`);
		s.base = started.baseUrl;
	});
	afterAll(async () => {
		if (started?.kind === "running") await started.stop();
	});
	const post = async (path: string, form: Record<string, string>, headers = {}) => {
		const res = await fetch(`${s.base}${path}`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
			body: new URLSearchParams({ client_id: "app", client_secret: secret, ...form }),
		});
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};
	return {
		token: (dpopProof: string) =>
			post("/oauth/token", { grant_type: "client_credentials" }, { dpop: dpopProof }),
		introspect: (token: unknown) => post("/oauth/introspect", { token: String(token) }),
	};
}

describe("without DPoP", () => {
	const { token } = running(false);
	it("ignores a DPoP header and issues a bearer token", async () => {
		const answer = await token(await proof());
		expect([answer.status, answer.body.token_type]).toEqual([200, "Bearer"]);
		expect(claimsOf(answer.body.access_token).cnf).toBeUndefined();
	});
});

describe.runIf(areaTarget().can("dpop"))("with DPoP", () => {
	const { token, introspect } = running(true);
	it("binds the token to the proof's key, and says so at introspection", async () => {
		const answer = await token(await proof());
		const cnf = { jkt: await calculateJwkThumbprint(await exportJWK(holder.publicKey), "sha256") };
		expect([answer.status, answer.body.token_type]).toEqual([200, "DPoP"]);
		expect(claimsOf(answer.body.access_token).cnf).toEqual(cnf);
		expect((await introspect(answer.body.access_token)).body).toMatchObject({
			active: true,
			token_type: "DPoP",
			cnf,
		});
	});

	it("accepts each proof once", async () => {
		const once = await proof();
		expect((await token(once)).status).toBe(200);
		const again = await token(once);
		expect([again.status, again.body.error]).toEqual([400, "invalid_dpop_proof"]);
	});

	it("refuses a proof for another method or another endpoint", async () => {
		for (const claims of [{ htm: "GET" }, { htu: `${issuer}/elsewhere` }]) {
			const answer = await token(await proof(claims));
			expect([answer.status, answer.body.error]).toEqual([400, "invalid_dpop_proof"]);
		}
	});
});
