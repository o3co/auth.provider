import { createHash, generateKeyPairSync, type KeyObject, randomUUID } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { exportJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CodeScene, codeScene } from "../src/main.ts";
import { backChannel, browserAt } from "../src/testing.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const signing = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");
const thief = generateKeyPairSync("ed25519");
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const fields: CodeScene = {
	issuer,
	keys: {
		signing: {
			kid: "rb",
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
			audiences: ["https://api.example"],
		},
	],
	users: [{ identifier: "alice", password: "correct horse battery" }],
	refresh: {},
	dpop: true,
};
const scene = codeScene(fields);

let running: Started;
let base = "";
beforeAll(async () => {
	if (!areaTarget().can("dpop")) return;
	running = await areaTarget().start(scene);
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
const proofBy = async (key: { publicKey: KeyObject; privateKey: KeyObject }) =>
	new SignJWT({
		htm: "POST",
		htu: `${issuer}/oauth/token`,
		iat: Math.floor(Date.now() / 1000),
		jti: randomUUID(),
	})
		.setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt", jwk: await exportJWK(key.publicKey) })
		.sign(key.privateKey);
async function token(
	form: Record<string, string>,
	key?: { publicKey: KeyObject; privateKey: KeyObject },
) {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: {
			...backChannel,
			"content-type": "application/x-www-form-urlencoded",
			...(key ? { dpop: await proofBy(key) } : {}),
		},
		body: new URLSearchParams({ ...form, client_id: "pub" }),
	});
	return { status: res.status, body: (await res.json()) as Record<string, string> };
}
async function redeem(key?: { publicKey: KeyObject; privateKey: KeyObject }) {
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
	return (
		await token(
			{ grant_type: "authorization_code", code, redirect_uri: callback, code_verifier: verifier },
			key,
		)
	).body;
}
const refresh = (refreshToken: string, key?: { publicKey: KeyObject; privateKey: KeyObject }) =>
	token({ grant_type: "refresh_token", refresh_token: refreshToken }, key);

describe.runIf(areaTarget().can("dpop"))("refresh: binding a public client's family", () => {
	it("never binds a family after it started, so a stolen token cannot lock its holder out [rfc9700-2.2.2-a]", async () => {
		const { refresh_token: first = "" } = await redeem();
		const stolen = await refresh(first, thief);
		expect(stolen.status).toBe(200);
		expect((await refresh(first)).body.error).toBe("invalid_grant");
		expect((await refresh(stolen.body.refresh_token ?? "", thief)).body.error).toBe(
			"invalid_grant",
		);
	});

	it("asks the binding a family started with, after taking a spent token as a reuse [rfc9449-5-c] [rfc9449-5-d] [rfc9700-2.2.2-a] [guarantee-6-b]", async () => {
		const { refresh_token: first = "" } = await redeem(holder);
		expect((await refresh(first)).body.error).toBe("invalid_grant");
		expect((await refresh(first, thief)).body.error).toBe("invalid_grant");
		const next = await refresh(first, holder);
		expect(next.status).toBe(200);
		expect((await refresh(first, thief)).body.error).toBe("invalid_grant");
		expect((await refresh(next.body.refresh_token ?? "", holder)).body.error).toBe("invalid_grant");
	});
});
