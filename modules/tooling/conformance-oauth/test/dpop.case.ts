import { generateKeyPairSync, randomUUID } from "node:crypto";
import { request } from "node:http";
import { areaTarget, type Started } from "@mod/conformance";
import { calculateJwkThumbprint, exportJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { oauthScene } from "../src/main.ts";

const issuer = "https://issuer.example";
const signing = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");
const secret = "app-secret-0123456789abcdef";
const scene = (dpop: boolean, nonces = false) =>
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
			// Held to DPoP, where DPoP is composed: a kind named must be one.
			...(dpop
				? [
						{
							id: "bound",
							kind: "confidential" as const,
							method: "client_secret_post" as const,
							secret,
							grants: ["client_credentials"],
							scopes: ["read"],
							defaultScopes: ["read"],
							bindingRequired: true,
							bindingKinds: ["dpop"],
						},
					]
				: []),
		],
		introspection: true,
		...(nonces ? { dpop: true, dpopNonce: true } : { dpop }),
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

function running(dpop: boolean, nonces = false) {
	let started: Started;
	const s = { base: "" };
	beforeAll(async () => {
		started = await areaTarget().start(scene(dpop, nonces));
		if (started.kind !== "running") throw new Error(`refused:\n${started.output}`);
		s.base = started.baseUrl;
	});
	afterAll(async () => {
		if (started?.kind === "running") await started.stop();
	});
	const post = async (path: string, form: Record<string, string>, headers = {}, client = "app") => {
		const res = await fetch(`${s.base}${path}`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
			body: new URLSearchParams({ client_id: client, client_secret: secret, ...form }),
		});
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};
	return {
		token: (dpopProof: string) =>
			post("/oauth/token", { grant_type: "client_credentials" }, { dpop: dpopProof }),
		/** A token request of the client held to DPoP, with a proof or without one. */
		bound: (dpopProof?: string) =>
			post(
				"/oauth/token",
				{ grant_type: "client_credentials" },
				dpopProof === undefined ? {} : { dpop: dpopProof },
				"bound",
			),
		introspect: (token: unknown) => post("/oauth/introspect", { token: String(token) }),
		/** A token request with a proof, and each `DPoP-Nonce` line of the answer as it came on the wire. */
		nonced: (dpopProof: string) =>
			new Promise<{ status: number; body: Record<string, unknown>; nonces: string[] }>(
				(answered, failed) => {
					const form = new URLSearchParams({
						client_id: "app",
						client_secret: secret,
						grant_type: "client_credentials",
					});
					const asking = request(
						`${s.base}/oauth/token`,
						{
							method: "POST",
							headers: {
								"content-type": "application/x-www-form-urlencoded",
								dpop: dpopProof,
							},
						},
						(res) => {
							const chunks: Buffer[] = [];
							res.on("data", (chunk: Buffer) => chunks.push(chunk));
							res.on("end", () => {
								const lines = res.rawHeaders;
								const nonces = lines.filter(
									(_, i) => i % 2 === 1 && lines[i - 1]?.toLowerCase() === "dpop-nonce",
								);
								const body = JSON.parse(Buffer.concat(chunks).toString()) as Record<
									string,
									unknown
								>;
								answered({ status: res.statusCode ?? 0, body, nonces });
							});
						},
					);
					asking.on("error", failed);
					asking.end(form.toString());
				},
			),
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
	const { token, introspect, bound } = running(true);
	it("refuses a token request without a proof from a client held to DPoP, and binds one with a proof [rfc9449-5.2-a]", async () => {
		const unproved = await bound();
		expect([unproved.status, unproved.body.error]).toEqual([400, "invalid_request"]);
		const proved = await bound(await proof());
		expect([proved.status, proved.body.token_type]).toEqual([200, "DPoP"]);
	});

	it("binds the token to the proof's key, and says so at introspection [rfc9449-5-b] [rfc9449-6.1-a] [rfc9449-6.2-a]", async () => {
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

	it("accepts each proof once [rfc9449-5-a]", async () => {
		const once = await proof();
		expect((await token(once)).status).toBe(200);
		const again = await token(once);
		expect([again.status, again.body.error]).toEqual([400, "invalid_dpop_proof"]);
	});

	it("refuses a proof for another method or another endpoint [rfc9449-4.3-f] [rfc9449-4.3-g] [rfc9449-5-a]", async () => {
		for (const claims of [{ htm: "GET" }, { htu: `${issuer}/elsewhere` }]) {
			const answer = await token(await proof(claims));
			expect([answer.status, answer.body.error]).toEqual([400, "invalid_dpop_proof"]);
		}
	});
});

describe.runIf(areaTarget().can("dpop"))("with DPoP nonces at the token endpoint", () => {
	const { nonced } = running(true, true);
	const nonceShape = /^\d+\.[A-Za-z0-9_-]+$/;
	it("refuses a proof without the current nonce in one DPoP-Nonce header, and takes one with it [rfc9449-8-b]", async () => {
		// The shape of a nonce, of a window long gone, under a MAC never made here.
		const forged = `1.${"A".repeat(43)}`;
		for (const [named, claims] of [
			["no nonce", {}],
			["a nonce not issued for now", { nonce: forged }],
		] as const) {
			const refused = await nonced(await proof(claims));
			expect([refused.status, refused.body.error], named).toEqual([400, "use_dpop_nonce"]);
			// One line on the wire, whatever a client would join several into.
			expect(refused.nonces, named).toHaveLength(1);
			expect(refused.nonces[0], named).toMatch(nonceShape);
		}
		const { nonces } = await nonced(await proof());
		const taken = await nonced(await proof({ nonce: nonces[0] }));
		expect([taken.status, taken.body.token_type]).toEqual([200, "DPoP"]);
	});

	it("names nonces only beside DPoP", () => {
		// @ts-expect-error A part without DPoP takes no nonce.
		const unasked = () => oauthScene({ issuer, clients: [], dpopNonce: true });
		expect(unasked).toBeTypeOf("function");
	});
});
