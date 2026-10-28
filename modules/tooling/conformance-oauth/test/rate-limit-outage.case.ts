import { generateKeyPairSync } from "node:crypto";
import { areaTarget, faultyTarget } from "@mod/conformance";
import { describe, expect, it } from "vitest";
import { oauthScene } from "../src/main.ts";

const issuer = "https://issuer.example";
const signing = generateKeyPairSync("ed25519");
const scene = oauthScene({
	issuer,
	keys: {
		signing: {
			kid: "ro",
			alg: "EdDSA",
			privatePem: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: signing.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [
		{
			id: "app",
			kind: "confidential",
			method: "client_secret_post",
			secret: "app-secret",
			// A request is counted before its client or grant is read; the grant is the one the token
			// endpoint asks to be composed at all.
			grants: ["client_credentials"],
			scopes: ["read"],
			defaultScopes: ["read"],
		},
	],
	rateLimitWhileStoreFails: "closed",
});

describe.runIf(areaTarget().can("store-fault:rate-limit"))(
	"rate limits: the store failing, by default",
	() => {
		const faulty = faultyTarget(scene);

		it("answers 503 at a rate-limited endpoint while the store cannot count", async () => {
			const answer = await faulty.whileDown(() =>
				fetch(`${faulty.base()}/oauth/token`, {
					method: "POST",
					headers: { "content-type": "application/x-www-form-urlencoded" },
					body: new URLSearchParams({
						grant_type: "client_credentials",
						client_id: "app",
						client_secret: "app-secret",
					}),
				}),
			);
			expect(answer.status).toBe(503);
		});
	},
);
