import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CodeScene, codeScene } from "../src/main.ts";

const issuer = "https://issuer.example";
const pair = generateKeyPairSync("ed25519");
const fields: CodeScene = {
	issuer,
	keys: {
		signing: {
			kid: "md",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [
		{
			id: "app",
			kind: "confidential",
			method: "client_secret_post",
			secret: "app-secret-0123456789abcdef",
			grants: ["authorization_code"],
			scopes: ["openid"],
			defaultScopes: ["openid"],
			redirectUris: ["https://app.example/cb"],
			firstParty: true,
		},
	],
	users: [{ identifier: "alice", password: "correct horse battery" }],
	discovery: true,
};

/** The scene's app running for the scenes of one describe, at the base it answers. */
function started(scene: CodeScene) {
	const at: { running?: Started; base: string } = { base: "" };
	beforeAll(async () => {
		at.running = await areaTarget().start(codeScene(scene));
		if (at.running.kind !== "running") throw new Error(`refused:\n${at.running.output}`);
		at.base = at.running.baseUrl;
	});
	afterAll(async () => {
		if (at.running?.kind === "running") await at.running.stop();
	});
	return at;
}

describe("the metadata document with the code flow", () => {
	const at = started(fields);
	it("tells where to authorize, that the answer is a code, and that PKCE is by S256", async () => {
		const res = await fetch(`${at.base}/.well-known/openid-configuration`);
		expect(res.status).toBe(200);
		const body = (await res.json()) as Record<string, unknown>;
		expect(body.authorization_endpoint).toBe(`${issuer}/oauth/authorize`);
		expect(body.response_types_supported).toEqual(["code"]);
		expect(body.code_challenge_methods_supported).toEqual(["S256"]);
	});

	it("names the algorithm ID tokens are signed with, and where the keys to check them are", async () => {
		const body = (await (
			await fetch(`${at.base}/.well-known/openid-configuration`)
		).json()) as Record<string, unknown>;
		expect(body.id_token_signing_alg_values_supported).toEqual(["EdDSA"]);
		// The key set is published at the root of the issuer's origin.
		expect(body.jwks_uri).toBe(new URL("/.well-known/jwks.json", issuer).href);
	});

	it("names openid, profile, email and groups as the scopes it supports", async () => {
		const body = (await (
			await fetch(`${at.base}/.well-known/openid-configuration`)
		).json()) as Record<string, unknown>;
		expect(body.scopes_supported).toEqual(["openid", "profile", "email", "groups"]);
	});
});

describe("the metadata document without client id documents composed", () => {
	const at = started({ ...fields, without: ["@mod/clients-cimd"] });

	it("does not say it takes client ids that are document URLs, as that part is not composed", async () => {
		const res = await fetch(`${at.base}/.well-known/openid-configuration`);
		const body = (await res.json()) as Record<string, unknown>;
		expect(body).not.toHaveProperty("client_id_metadata_document_supported");
	});
});
