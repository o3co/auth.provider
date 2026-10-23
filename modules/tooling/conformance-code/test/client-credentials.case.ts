import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../src/main.ts";
import { backChannel } from "../src/testing.ts";

// A scene of its own, so the code flow's checks run where the client credentials grant is not composed.
const issuer = "https://issuer.example";
const pair = generateKeyPairSync("ed25519");
const svc: ClientScene = {
	id: "svc",
	kind: "confidential",
	method: "client_secret_post",
	secret: "svc-secret-0123456789abcdef",
	grants: ["client_credentials"],
	scopes: ["openid", "read"],
	defaultScopes: ["read"],
};

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(
		codeScene({
			issuer,
			keys: {
				signing: {
					kid: "cc",
					alg: "EdDSA",
					privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
					publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
				},
			},
			clients: [svc],
			users: [],
		}),
	);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

describe("OpenID Connect: the client credentials grant", () => {
	it("gives no ID token for openid asked of it", async () => {
		const res = await fetch(`${base}/oauth/token`, {
			method: "POST",
			headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "client_credentials",
				client_id: svc.id,
				client_secret: svc.secret ?? "",
				scope: "openid read",
			}),
		});
		const body = (await res.json()) as Record<string, unknown>;
		expect(res.status).toBe(200);
		expect(body.access_token).toEqual(expect.any(String));
		expect(body.id_token).toBeUndefined();
	});
});
