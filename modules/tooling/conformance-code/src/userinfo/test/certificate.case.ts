import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { type Issued, issue, pemOf, thumbprintOf } from "@mod/conformance-mtls";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../../main.ts";
import { backChannel } from "../../testing.ts";

const issuer = "https://issuer.example";
const header = "x-client-cert";
const pair = generateKeyPairSync("ed25519");
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
					kid: "uc",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			clients: [svc],
			users: [],
			mtls: { header: { dialect: "pem", name: header }, trustedProxies: ["127.0.0.1"] },
			userinfo: true,
		}),
	);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

/** The certificate as the trusted proxy forwards it. */
const forwarded = (issued: Issued) => ({ [header]: encodeURIComponent(pemOf(issued.der)) });
/** An access token bound to the certificate, by the client's own credentials. */
async function boundTo(issued: Issued) {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: {
			...backChannel,
			"content-type": "application/x-www-form-urlencoded",
			...forwarded(issued),
		},
		body: new URLSearchParams({
			grant_type: "client_credentials",
			client_id: svc.id,
			client_secret: svc.secret ?? "",
		}),
	});
	const { access_token: token = "" } = (await res.json()) as Record<string, string>;
	const claims = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString());
	expect(claims.cnf).toEqual({ "x5t#S256": thumbprintOf(issued.der) });
	return token;
}
async function userinfo(token: string, certificate?: Issued) {
	const res = await fetch(`${base}/oauth/userinfo`, {
		headers: {
			...backChannel,
			authorization: `Bearer ${token}`,
			...(certificate ? forwarded(certificate) : {}),
		},
	});
	const text = await res.text();
	return {
		status: res.status,
		challenge: res.headers.get("www-authenticate") ?? "",
		body: (text ? JSON.parse(text) : {}) as Record<string, unknown>,
	};
}

describe("OpenID Connect userinfo: a token bound to the client's certificate (mTLS)", () => {
	it("answers the client that presents the certificate the token is bound to", async () => {
		const own = await issue({ cn: "client" });
		const answer = await userinfo(await boundTo(own), own);
		expect([answer.status, Object.keys(answer.body)]).toEqual([200, ["sub"]]);
	});

	it("refuses the token with another certificate, or with none", async () => {
		const own = await issue({ cn: "client" });
		const token = await boundTo(own);
		for (const [name, certificate] of [
			["another certificate", await issue({ cn: "other" })],
			["no certificate", undefined],
		] as const) {
			const answer = await userinfo(token, certificate);
			expect([name, answer.status], name).toEqual([name, 401]);
			expect(answer.challenge, name).toMatch(/^Bearer/);
		}
	});
});
