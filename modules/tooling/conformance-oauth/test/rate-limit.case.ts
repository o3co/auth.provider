import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, expect, it } from "vitest";
import { oauthScene } from "../src/main.ts";

const pair = generateKeyPairSync("ed25519");
const scene = oauthScene({
	issuer: "https://issuer.example",
	keys: {
		signing: {
			kid: "rl",
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
			// Its requests fail authentication before any grant is read; the grant is the one the
			// token endpoint asks to be composed at all.
			grants: ["client_credentials"],
			scopes: ["read"],
		},
	],
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

it("limits requests to the token endpoint per source, before the client is authenticated [rfc6749-2.3.1-c] [guarantee-10-a]", async () => {
	const post = () =>
		fetch(`${base}/oauth/token`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "client_credentials",
				client_id: "app",
				client_secret: "wrong",
			}),
		});
	for (let i = 0; i < 60; i++) expect((await post()).status).toBe(401);
	const limited = await post();
	expect(limited.status).toBe(429);
	expect(Number(limited.headers.get("retry-after"))).toBeGreaterThan(0);
	expect(((await limited.json()) as { error: string }).error).toBe("rate_limited");
});
