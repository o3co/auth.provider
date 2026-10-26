import { generateKeyPairSync } from "node:crypto";
import { sceneOf } from "@mod/conformance";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { describe, expect, it } from "vitest";
import { secondFactorArea } from "../src/main.ts";
import { issuer, password, running } from "../src/testing.ts";

const pair = generateKeyPairSync("ed25519");
const scene = sceneOf(
	keysArea.part({
		signing: {
			kid: "backoff",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	}),
	identityArea.part({
		origin: issuer,
		users: [{ identifier: "ola", password }],
		login: { attempts: 100, windowSeconds: 600 },
	}),
	secondFactorArea.part({
		mode: "optional",
		// Each hold doubles from one second: uncapped, the third would be four.
		lockout: { threshold: 1, backoffSeconds: 1, maxBackoffSeconds: 2, budget: 10, hardLimit: 10 },
	}),
);
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe("H. the second-factor lockout's longest hold", () => {
	const s = running(scene);

	/** A wrong TOTP code in a fresh held login of the user: its status, and the wait it names. */
	const guess = async (user: string) => {
		const { b, transaction } = await s.held(user);
		const factor = (await b.factors(transaction)).find((f) => f.kind === "totp");
		const res = await b.exchange("POST", "/session/mfa/verify", {
			transaction_id: transaction,
			factor_id: factor?.id ?? "",
			proof: "000000",
		});
		return { status: res.status, wait: res.headers.get("retry-after") };
	};

	it("doubles each hold after a failure past it, but never names a wait longer than the longest hold [rfc6749-10.10-d]", async () => {
		await s.enrol("ola");
		const waits: (string | null)[] = [];
		for (const quiet of [1100, 2100, 0]) {
			expect((await guess("ola")).status).toBe(401);
			const held = await guess("ola");
			expect(held.status).toBe(429);
			waits.push(held.wait);
			await pause(quiet);
		}
		expect(waits).toEqual(["1", "2", "2"]);
	});
});
