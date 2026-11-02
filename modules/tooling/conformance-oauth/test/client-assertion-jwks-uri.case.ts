import { generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { areaTarget, type Started } from "@mod/conformance";
import { type JWTPayload, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { oauthScene } from "../src/main.ts";

const issuer = "https://issuer.example";
const signing = generateKeyPairSync("ed25519");
const clientKey = generateKeyPairSync("ec", { namedCurve: "P-256" });

/** The client's key set, published on loopback. */
const keySet = createServer((_request, response) => {
	response.writeHead(200, { "content-type": "application/json" });
	response.end(
		JSON.stringify({
			keys: [{ ...clientKey.publicKey.export({ format: "jwk" }), kid: "k1", use: "sig" }],
		}),
	);
});

let running: Started;
let base = "";
beforeAll(async () => {
	await new Promise<void>((done) => keySet.listen(0, "127.0.0.1", done));
	const { port } = keySet.address() as AddressInfo;
	const scene = oauthScene({
		issuer,
		keys: {
			signing: {
				kid: "ca",
				alg: "EdDSA",
				privatePem: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: signing.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		clients: [
			{
				id: "app",
				kind: "confidential",
				method: "private_key_jwt",
				jwksUri: `http://127.0.0.1:${port}/jwks`,
				grants: ["client_credentials"],
				scopes: ["read"],
				defaultScopes: ["read"],
			},
		],
	});
	running = await areaTarget().start(scene);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
	await new Promise<void>((done) => keySet.close(() => done()));
});

const now = () => Math.floor(Date.now() / 1000);
const claims = (extra: Record<string, unknown> = {}): JWTPayload => ({
	iss: "app",
	sub: "app",
	aud: issuer,
	exp: now() + 60,
	iat: now(),
	jti: `j-${Math.random()}`,
	...extra,
});
const token = async (assertion: string) => {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "client_credentials",
			client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			client_assertion: assertion,
		}),
	});
	return { status: res.status, body: (await res.json()) as Record<string, unknown> };
};

describe("client authentication by private_key_jwt, with keys at the client's jwks_uri", () => {
	it("authenticates a client by an assertion signed with a key its jwks_uri publishes", async () => {
		const signed = await new SignJWT(claims())
			.setProtectedHeader({ alg: "ES256", kid: "k1" })
			.sign(clientKey.privateKey);
		expect((await token(signed)).status).toBe(200);
	});

	it("refuses an assertion signed with a key its jwks_uri does not publish [rfc7523-3-u] [rfc7521-5.2-n]", async () => {
		const stranger = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
		const signed = await new SignJWT(claims())
			.setProtectedHeader({ alg: "ES256", kid: "k1" })
			.sign(stranger);
		const answer = await token(signed);
		expect([answer.status, answer.body.error]).toEqual([401, "invalid_client"]);
	});
});
