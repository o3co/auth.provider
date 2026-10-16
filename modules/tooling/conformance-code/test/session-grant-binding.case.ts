import { generateKeyPairSync, randomUUID } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { exportJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../src/main.ts";
import { browserAt } from "../src/testing.ts";

const issuer = "https://issuer.example";
const signing = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");
const scene = codeScene({
	issuer,
	keys: {
		signing: {
			kid: "sgb",
			alg: "EdDSA",
			privatePem: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: signing.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [
		{
			id: "spa",
			kind: "public",
			method: "none",
			grants: ["session"],
			scopes: ["read"],
			defaultScopes: [],
			audiences: ["https://api.example"],
		},
	],
	users: [{ identifier: "alice", password: "correct horse battery" }],
	sessionGrant: true,
	dpop: true,
});

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
const proof = async () =>
	new SignJWT({
		htm: "POST",
		htu: `${issuer}/oauth/token`,
		iat: Math.floor(Date.now() / 1000),
		jti: randomUUID(),
	})
		.setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt", jwk: await exportJWK(holder.publicKey) })
		.sign(holder.privateKey);

describe.runIf(areaTarget().can("dpop"))("session grant: binding", () => {
	it("binds the token to the key the request proves", async () => {
		const res = await fetch(`${base}/oauth/token`, {
			method: "POST",
			headers: browser.headers({
				"content-type": "application/x-www-form-urlencoded",
				cookie: await browser.login(),
				origin: issuer,
				dpop: await proof(),
			}),
			body: new URLSearchParams({ grant_type: "session", client_id: "spa" }),
		});
		expect(res.status).toBe(200);
		expect(((await res.json()) as { token_type?: string }).token_type).toBe("DPoP");
	});
});
