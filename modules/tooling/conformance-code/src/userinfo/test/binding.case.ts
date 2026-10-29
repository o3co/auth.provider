import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { exportJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../../main.ts";
import { backChannel, succeeded } from "../../testing.ts";

const issuer = "https://issuer.example";
const pair = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");
const stranger = generateKeyPairSync("ed25519");
const svc: ClientScene = {
	id: "svc",
	kind: "confidential",
	method: "client_secret_post",
	secret: "svc-secret-0123456789abcdef",
	grants: ["client_credentials"],
	// userinfo serves only a token issued for openid.
	scopes: ["openid", "read"],
	defaultScopes: ["openid", "read"],
};

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(
		codeScene({
			issuer,
			keys: {
				signing: {
					kid: "ub",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			clients: [svc],
			users: [],
			dpop: true,
			// Sets the legacy build up for DPoP, which the oauth area does not.
			dpopAtResources: true,
			userinfo: true,
		}),
	);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

/** A DPoP proof (RFC 9449 §4) by `key`, for `htm` at `path`, bound to `token` when given, its claims written over by `over`. */
async function proof(path: string, htm: string, token?: string, key = holder, over = {}) {
	const ath = token && createHash("sha256").update(token).digest("base64url");
	return new SignJWT({
		htm,
		htu: `${issuer}${path}`,
		iat: Math.floor(Date.now() / 1000),
		jti: randomUUID(),
		...(ath ? { ath } : {}),
		...over,
	})
		.setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt", jwk: await exportJWK(key.publicKey) })
		.sign(key.privateKey);
}
/** A DPoP-bound access token for the client, by its own credentials. */
async function boundToken() {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: {
			...backChannel,
			"content-type": "application/x-www-form-urlencoded",
			dpop: await proof("/oauth/token", "POST"),
		},
		body: new URLSearchParams({
			grant_type: "client_credentials",
			client_id: svc.id,
			client_secret: svc.secret ?? "",
		}),
	});
	const answer = (await succeeded(res, "the token endpoint")) as Record<string, string>;
	expect(answer.token_type).toBe("DPoP");
	return answer.access_token ?? "";
}
async function userinfo(headers: Record<string, string>) {
	const res = await fetch(`${base}/oauth/userinfo`, { headers: { ...backChannel, ...headers } });
	const text = await res.text();
	return {
		status: res.status,
		challenge: res.headers.get("www-authenticate") ?? "",
		body: (text ? JSON.parse(text) : {}) as Record<string, unknown>,
	};
}

describe("OpenID Connect userinfo: a token bound to its holder's key (DPoP)", () => {
	it("answers the holder that proves its key for this request and this token [rfc9449-5-b]", async () => {
		const token = await boundToken();
		const answer = await userinfo({
			authorization: `DPoP ${token}`,
			dpop: await proof("/oauth/userinfo", "GET", token),
		});
		expect([answer.status, Object.keys(answer.body)]).toEqual([200, ["sub"]]);
	});

	it("refuses the token presented as a Bearer token, challenging for DPoP, as the token itself says it is bound [rfc9449-7.2-a] [rfc9449-6-a] [guarantee-6-a]", async () => {
		const answer = await userinfo({ authorization: `Bearer ${await boundToken()}` });
		expect(answer.status).toBe(401);
		expect(answer.challenge).toMatch(/^DPoP/);
	});

	it("refuses a proof by another key, and one bound to another token, granting nothing on the token alone [rfc9449-4.3-k] [rfc9449-4.3-l] [rfc9449-7.1-b]", async () => {
		const token = await boundToken();
		const other = await userinfo({
			authorization: `DPoP ${token}`,
			dpop: await proof("/oauth/userinfo", "GET", token, stranger),
		});
		expect(other.status).toBe(401);
		const elsewhere = await userinfo({
			authorization: `DPoP ${token}`,
			dpop: await proof("/oauth/userinfo", "GET", "another token"),
		});
		expect(elsewhere.status).toBe(401);
	});

	it("grants nothing until every check of the proof has passed: its method, its URI, its time, its signature and its one use [rfc9449-7.1-b]", async () => {
		const token = await boundToken();
		const at = (dpop: string) => userinfo({ authorization: `DPoP ${token}`, dpop });
		const old = Math.floor(Date.now() / 1000) - 3600;
		for (const [name, dpop] of [
			["another method", await proof("/oauth/userinfo", "POST", token)],
			["another URI", await proof("/oauth/token", "GET", token)],
			["an hour old", await proof("/oauth/userinfo", "GET", token, holder, { iat: old })],
		] as const) {
			expect((await at(dpop)).status, name).toBe(401);
		}
		// alg none, written by hand as no JOSE library signs one: the header and claims a proof needs, and no signature.
		const part = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
		const unsigned = `${part({ alg: "none", typ: "dpop+jwt", jwk: await exportJWK(holder.publicKey) })}.${part(
			{
				htm: "GET",
				htu: `${issuer}/oauth/userinfo`,
				iat: Math.floor(Date.now() / 1000),
				jti: randomUUID(),
				ath: createHash("sha256").update(token).digest("base64url"),
			},
		)}.`;
		expect((await at(unsigned)).status, "alg none").toBe(401);
		const once = await proof("/oauth/userinfo", "GET", token);
		expect((await at(once)).status).toBe(200);
		expect((await at(once)).status).toBe(401);
	});

	it("refuses the token under the DPoP scheme without a proof [rfc9449-7.1-a]", async () => {
		const answer = await userinfo({ authorization: `DPoP ${await boundToken()}` });
		expect(answer.status).toBe(401);
		expect(answer.challenge).toMatch(/^DPoP/);
	});

	it("takes no token from Proxy-Authorization, and never challenges in Proxy-Authenticate [rfc9449-7.1-e]", async () => {
		const token = await boundToken();
		const res = await fetch(`${base}/oauth/userinfo`, {
			headers: {
				...backChannel,
				"proxy-authorization": `DPoP ${token}`,
				dpop: await proof("/oauth/userinfo", "GET", token),
			},
		});
		expect(res.status).toBe(401);
		expect(res.headers.get("proxy-authenticate")).toBeNull();
	});
});
