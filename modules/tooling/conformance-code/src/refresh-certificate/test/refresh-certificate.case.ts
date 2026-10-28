import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { type Issued, issue, pemOf, thumbprintOf } from "@mod/conformance-mtls";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../../main.ts";
import { backChannel, browserAt } from "../../testing.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const header = "x-client-cert";
const signing = generateKeyPairSync("ed25519");
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(
		codeScene({
			issuer,
			keys: {
				signing: {
					kid: "rc",
					alg: "EdDSA",
					privatePem: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: signing.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			clients: [
				{
					id: "pub",
					kind: "public",
					method: "none",
					grants: ["authorization_code", "refresh_token"],
					scopes: ["openid", "read"],
					defaultScopes: ["read"],
					redirectUris: [callback],
					firstParty: true,
				},
			],
			users: [{ identifier: "alice", password: "correct horse battery" }],
			refresh: {},
			mtls: { header: { dialect: "pem", name: header }, trustedProxies: ["127.0.0.1"] },
		}),
	);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

const browser = browserAt(() => base, issuer, {
	username: "alice",
	password: "correct horse battery",
});
/** A request to the token endpoint as the public client, presenting the certificate where given. */
async function token(form: Record<string, string>, certificate?: Issued) {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: {
			...backChannel,
			"content-type": "application/x-www-form-urlencoded",
			...(certificate ? { [header]: encodeURIComponent(pemOf(certificate.der)) } : {}),
		},
		body: new URLSearchParams({ ...form, client_id: "pub" }),
	});
	return { status: res.status, body: (await res.json()) as Record<string, string> };
}
async function redeem(certificate: Issued) {
	browser.forget();
	const res = await browser.authorize({
		response_type: "code",
		client_id: "pub",
		redirect_uri: callback,
		state: "s1",
		scope: "openid read",
		code_challenge: challenge,
		code_challenge_method: "S256",
	});
	const code = res.at?.searchParams.get("code") ?? "";
	const form = { grant_type: "authorization_code", code, redirect_uri: callback };
	return (await token({ ...form, code_verifier: verifier }, certificate)).body;
}
const refresh = (refreshToken: string, certificate?: Issued) =>
	token({ grant_type: "refresh_token", refresh_token: refreshToken }, certificate);
const boundOf = (jwt: string | undefined) =>
	JSON.parse(Buffer.from((jwt ?? "").split(".")[1] ?? "", "base64url").toString()).cnf;

describe("refresh: a public client's family bound to its certificate (mTLS)", () => {
	it("binds each refreshed token to the certificate the family started with [rfc8705-4-a]", async () => {
		const own = await issue({ cn: "pub" });
		const first = await redeem(own);
		expect(boundOf(first.access_token)).toEqual({ "x5t#S256": thumbprintOf(own.der) });
		let current = first.refresh_token ?? "";
		for (const round of ["first refresh", "second refresh"]) {
			const next = await refresh(current, own);
			expect(next.status, round).toBe(200);
			expect(boundOf(next.body.access_token), round).toEqual({
				"x5t#S256": thumbprintOf(own.der),
			});
			current = next.body.refresh_token ?? "";
		}
	});

	it("redeems a refresh token only with its family's certificate, refusing one with another or none [rfc8705-4-b]", async () => {
		const own = await issue({ cn: "pub" });
		const { refresh_token: current = "" } = await redeem(own);
		for (const [name, certificate] of [
			["no certificate", undefined],
			["another certificate", await issue({ cn: "other" })],
		] as const) {
			expect((await refresh(current, certificate)).body.error, name).toBe("invalid_grant");
		}
		// A refusal for the binding spends nothing, so the holder of the certificate goes on.
		expect((await refresh(current, own)).status).toBe(200);
	});
});
