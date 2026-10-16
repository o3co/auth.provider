import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../src/main.ts";
import { browserAt } from "../src/testing.ts";

const issuer = "https://issuer.example";
const callback = "https://third.example/cb";
const pair = generateKeyPairSync("ed25519");
const challenge = createHash("sha256").update("v".repeat(43)).digest("base64url");
const password = "correct horse battery";
const third = {
	id: "third",
	kind: "confidential",
	method: "client_secret_post",
	secret: "third-secret-0123456789abcdef",
	grants: ["authorization_code"],
	scopes: ["openid", "read"],
	redirectUris: [callback],
} as const;
const scene = codeScene({
	issuer,
	keys: {
		signing: {
			kid: "wc",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [
		third,
		{ ...third, id: "app", secret: "app-secret-0123456789abcdef", firstParty: true },
	],
	users: [{ identifier: "alice", password }],
	withoutConsent: true,
});

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

const request = (client: string) => ({
	response_type: "code",
	client_id: client,
	redirect_uri: callback,
	state: "s1",
	scope: "openid",
	code_challenge: challenge,
	code_challenge_method: "S256",
});

describe("authorize: without the consent step", () => {
	it("refuses a client that is not first-party, once logged in, with unauthorized_client", async () => {
		const browser = browserAt(() => base, issuer, { username: "alice", password });
		const before = await browser.authorize(request("third"), false);
		expect(`${before.at?.origin}${before.at?.pathname}`).toBe(`${issuer}/login`);
		const res = await browser.authorize(request("third"));
		expect(res.status).toBe(302);
		expect(`${res.at?.origin}${res.at?.pathname}`).toBe(callback);
		expect([
			res.at?.searchParams.get("error"),
			res.at?.searchParams.get("error_description"),
			res.at?.searchParams.get("state"),
			res.at?.searchParams.get("iss"),
			res.at?.searchParams.has("code"),
		]).toEqual([
			"unauthorized_client",
			"client is not authorized for the authorization endpoint",
			"s1",
			issuer,
			false,
		]);
	});

	it("still gives a first-party client its code", async () => {
		const browser = browserAt(() => base, issuer, { username: "alice", password });
		const res = await browser.authorize(request("app"));
		expect(`${res.at?.origin}${res.at?.pathname}`).toBe(callback);
		expect(res.at?.searchParams.has("code")).toBe(true);
	});
});
