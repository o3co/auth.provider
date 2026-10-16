import { generateKeyPairSync } from "node:crypto";
import { areaTarget, faultyTarget } from "@mod/conformance";
import { afterAll, describe, expect, it } from "vitest";
import { federationScene } from "../src/main.ts";
import { browser, probeClient } from "./browser.ts";
import { fakeUpstream } from "./upstream.ts";

const origin = "https://issuer.example";
const start = "/session/oauth/federation/corp";
const pair = generateKeyPairSync("ed25519");
const client = { id: "as-client", secret: "as-client-secret-0123456789" };

const upstream = await fakeUpstream(client);
afterAll(() => upstream.stop());

const scene = federationScene({
	origin,
	keys: {
		signing: {
			kid: "fed",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	idps: [
		{ name: "corp", issuer: upstream.issuer, clientId: client.id, clientSecret: client.secret },
	],
	landing: "https://app.example/home",
	returnTargets: [],
	users: [],
	clients: [probeClient],
});

describe.runIf(areaTarget().can("store-fault:federation"))("federation: the store failing", () => {
	const faulty = faultyTarget(scene);

	it("answers a start 503 temporarily_unavailable while the store is unreachable, and starts after", async () => {
		const b = browser(faulty.base, origin);
		const answer = await faulty.whileDown(() => b.get(start));
		expect([answer.status, answer.body?.error]).toEqual([503, "temporarily_unavailable"]);
		expect((await b.get(start)).status).toBe(302);
	});
});
