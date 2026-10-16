import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { browserAt } from "@mod/conformance-code/testing";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { exchangeScene } from "../src/main.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const exchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
const accessType = "urn:ietf:params:oauth:token-type:access_token";
const password = "correct horse battery";
const signing = generateKeyPairSync("ed25519");
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const secret = "gateway-secret-0123456789abcdef";
const gateway: ClientScene = {
	id: "gateway",
	kind: "confidential",
	method: "client_secret_post",
	secret,
	grants: ["authorization_code", "client_credentials", exchangeGrant],
	scopes: ["openid", "read"],
	defaultScopes: ["read"],
	redirectUris: [callback],
	firstParty: true,
};
/** Token exchange with the gate on, over the users file: alice's email is stated verified. */
const scene = exchangeScene({
	issuer,
	keys: {
		signing: {
			kid: "ve",
			alg: "EdDSA",
			privatePem: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: signing.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [gateway],
	users: [{ identifier: "alice", password, emailVerified: true }],
	verifiedEmail: true,
});
/** The legacy build refuses to start with the gate and token exchange, as its users file cannot find a user by subject. */
const unstartable = areaTarget().differs("email-gate-without-subject-lookup");

describe("O. verified email with token exchange over the users file", () => {
	it("starts on the new target, the legacy build refusing to", async () => {
		const started = await areaTarget().start(scene);
		if (started.kind === "running") await started.stop();
		expect(started.kind).toBe(unstartable ? "refused" : "running");
		if (started.kind === "refused") expect(started.output).toMatch(/requireEmailVerified/);
	});
});

describe.runIf(!unstartable)("L. verified email: token exchange", () => {
	let running: Started;
	let base = "";
	beforeAll(async () => {
		running = await areaTarget().start(scene);
		if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
		base = running.baseUrl;
	});
	afterAll(async () => {
		if (running?.kind === "running") await running.stop();
	});
	const token = async (form: Record<string, string>) => {
		const res = await fetch(`${base}/oauth/token`, {
			method: "POST",
			headers: {
				"x-forwarded-proto": "https",
				"x-forwarded-for": "198.51.100.21",
				"content-type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({ ...form, client_id: gateway.id, client_secret: secret }),
		});
		return { status: res.status, body: (await res.json()) as Record<string, string> };
	};
	const exchange = (subject: string | undefined) =>
		token({
			grant_type: exchangeGrant,
			subject_token: subject ?? "",
			subject_token_type: accessType,
		});

	it("exchanges a token of a user whose email is stated verified", async () => {
		const browser = browserAt(() => base, issuer, { username: "alice", password });
		const answer = await browser.authorize({
			response_type: "code",
			client_id: gateway.id,
			redirect_uri: callback,
			state: "s1",
			scope: "openid read",
			code_challenge: challenge,
			code_challenge_method: "S256",
		});
		const subject = await token({
			grant_type: "authorization_code",
			code: answer.at?.searchParams.get("code") ?? "",
			redirect_uri: callback,
			code_verifier: verifier,
		});
		expect((await exchange(subject.body.access_token)).status).toBe(200);
	});

	it("refuses a client's own token, which names no user, saying why", async () => {
		const own = await token({ grant_type: "client_credentials" });
		expect(own.status).toBe(200);
		const res = await exchange(own.body.access_token);
		expect([res.status, res.body.error_description]).toEqual([
			400,
			"email address is not verified",
		]);
		if (!areaTarget().differs("email-refusal-code-exchange")) {
			expect(res.body.error).toBe("invalid_grant");
		}
	});
});
