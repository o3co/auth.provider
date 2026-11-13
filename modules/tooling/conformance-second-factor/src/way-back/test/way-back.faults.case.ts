import { generateKeyPairSync, randomBytes } from "node:crypto";
import { type AreaScene, sceneOf } from "@mod/conformance";
import {
	type FakeSmtp,
	fakeSmtp,
	type Instance,
	startDeployment,
	startTopology,
	type Topology,
} from "@mod/conformance/testing";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { afterEach, describe, expect, it } from "vitest";
import { secondFactorArea } from "../../main.ts";
import { beginBinding, browser, issuer, password, totp } from "../../testing.ts";

// A code by mail bound as a way back while the second factor was optional, as 0.19 let it be under
// required too, then the deployment started again under required on the same store and sealing key.

const pair = generateKeyPairSync("ed25519");
const user = "alice";
const address = "alice@example.com";
const sealKey = randomBytes(32).toString("base64");

/** The scene in the mode, on the Redis store, its mail to the relay, one failure holding the factors. */
const sceneIn = (mode: "optional" | "required", smtp: FakeSmtp): AreaScene => ({
	...sceneOf(
		keysArea.part({
			signing: {
				kid: "way-back",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		}),
		identityArea.part({
			origin: issuer,
			users: [{ identifier: user, password, email: address }],
			login: { attempts: 100, windowSeconds: 600 },
		}),
		secondFactorArea.part({
			mode,
			mail: { host: smtp.host, port: smtp.port, addsSecondFactor: false },
			lockout: { threshold: 1, backoffSeconds: 600, budget: 10, hardLimit: 10 },
			sealKey,
		}),
	),
	storeFaults: true,
});

/** What a scene started and stops however it ends. */
const stops: (() => Promise<unknown>)[] = [];
afterEach(async () => {
	for (const stop of stops.splice(0).reverse()) await stop();
});

async function started(topology: Topology, scene: AreaScene) {
	const deployment = await startDeployment({
		name: `way-back-${randomBytes(4).toString("hex")}`,
		scene,
		topology,
		instances: 1,
	});
	return { instance: deployment.instances[0] as Instance, stop: () => deployment.stop() };
}

/** A login at the instance a second factor holds: its browser, its transaction and the factors it lists. */
async function heldAt(i: Instance) {
	const b = browser(() => i.baseUrl);
	const answer = await b.login(user);
	expect([answer.status, answer.body.error]).toEqual([403, "mfa_required"]);
	const transaction = String(answer.body.transaction);
	return { b, transaction, factors: await b.factors(transaction) };
}

describe("a code by mail bound as a way back, then a required second factor", () => {
	it("lists it at no login, proves nothing by it and lifts no hold", async () => {
		const smtp = await fakeSmtp();
		stops.push(() => smtp.stop());
		const topology = await startTopology({ replicas: 0 });
		stops.push(() => topology.stop());

		// Optional: TOTP, then the code by mail bound from a session the TOTP proved.
		const first = await started(topology, sceneIn("optional", smtp));
		const signedIn = browser(() => first.instance.baseUrl);
		expect((await signedIn.login(user)).status).toBe(200);
		const totpBegun = await beginBinding(signedIn, { kind: "totp" }, undefined);
		const secret = String(totpBegun.body.secret);
		const totpDone = await signedIn.send("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(totpBegun.body.transaction),
			proof: totp(secret),
		});
		expect(totpDone.status).toBe(200);
		const held = await heldAt(first.instance);
		const proved = await held.b.send("POST", "/session/mfa/verify", {
			transaction_id: held.transaction,
			factor_id: held.factors.find((f) => f.kind === "totp")?.id ?? "",
			proof: totp(secret, 1),
		});
		expect(proved.status).toBe(200);
		const begun = await held.b.send("POST", "/session/mfa/enrollment", { kind: "email" });
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		const code = /\b([0-9A-Z]{16})\b/.exec(smtp.latestTo(address)?.text ?? "")?.[1] ?? "";
		const bound = await held.b.send("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: code,
		});
		expect(bound.status, JSON.stringify(bound.body)).toBe(200);
		const email = (await heldAt(first.instance)).factors.find((f) => f.kind === "email")?.id;
		expect(email).toBeDefined();
		await first.stop();

		// Required, on the same store and sealing key.
		const second = await started(topology, sceneIn("required", smtp));
		stops.push(second.stop);
		const login = await heldAt(second.instance);
		expect(login.factors.map((f) => f.kind)).not.toContain("email");
		const totpId = login.factors.find((f) => f.kind === "totp")?.id ?? "";
		/** A proof of the factor in a fresh login the second factor holds. */
		const verify = async (factor: string, proof: string) => {
			const { b, transaction } = await heldAt(second.instance);
			return b.send("POST", "/session/mfa/verify", {
				transaction_id: transaction,
				factor_id: factor,
				proof,
			});
		};
		// One failure holds the factors; the way back, which 0.19 would prove, is no factor here.
		expect((await verify(totpId, "000000")).status).toBe(401);
		const byMail = await verify(email ?? "", "000000");
		expect([byMail.status, byMail.body.error_description]).toEqual([400, "unknown factor"]);
		expect((await verify(totpId, totp(secret, 2))).status).toBe(429);
	});
});
