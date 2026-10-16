import { generateKeyPairSync } from "node:crypto";
import { areaTarget, auditEvents, sceneOf } from "@mod/conformance";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { describe, expect, it } from "vitest";
import { type SecondFactorPart, secondFactorArea } from "../src/main.ts";
import { issuer, letInByRecovery, password, running, totp } from "../src/testing.ts";

const pair = generateKeyPairSync("ed25519");
const release = "/session/mfa/lock/release";
const sceneFor = (users: string[], lockout?: SecondFactorPart["lockout"]) =>
	sceneOf(
		keysArea.part({
			signing: {
				kid: "lock-release",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		}),
		identityArea.part({
			origin: issuer,
			users: users.map((identifier) => ({ identifier, password })),
			login: { attempts: 100, windowSeconds: 600 },
		}),
		secondFactorArea.part({ mode: "optional", ...(lockout ? { lockout } : {}) }),
	);
const refused = {
	error: "mfa_lock_release_refused",
	error_description: "Change the account's password, sign in again, then release",
	reason: "not_revoked_since",
};

type Running = ReturnType<typeof running>;

/** Fails `times` TOTP proofs in held logins of the user, as a guesser would. */
async function guessed(s: Running, user: string, times: number) {
	for (let i = 0; i < times; i++) {
		const { b, transaction } = await s.held(user);
		const factor = (await b.factors(transaction)).find((f) => f.kind === "totp");
		await b.send("POST", "/session/mfa/verify", {
			transaction_id: transaction,
			factor_id: factor?.id ?? "",
			proof: "000000",
		});
	}
}

/** A browser the user signed in to with a recovery code. */
async function inByRecovery(s: Running, user: string, code: string) {
	const { b, transaction } = await s.held(user);
	expect((await letInByRecovery(b, transaction, code)).status).toBe(200);
	return b;
}

describe("H. a user's own release of the second-factor lockout", () => {
	const s = running(sceneFor(["ana", "ben", "cid", "eve", "fay"]));

	it("releases the lockout of a session a recovery code let in, and answers the same again", async () => {
		const { codes } = await s.enrol("ana");
		const b = await inByRecovery(s, "ana", codes[0] ?? "");
		const first = await b.send("POST", release);
		expect([first.status, first.body]).toEqual([200, { lock: "released" }]);
		expect((await b.send("POST", release)).body).toEqual({ lock: "released" });
	});

	it.runIf(areaTarget().can(auditEvents.need))(
		"records a release once, with what it cleared",
		async () => {
			const { codes } = await s.enrol("eve");
			const b = await inByRecovery(s, "eve", codes[0] ?? "");
			const first = await s.trail().during(() => b.send("POST", release));
			const again = await s.trail().during(() => b.send("POST", release));
			const recovered = [...first.events, ...again.events].filter(
				(e) => e.kind === "mfa.lock.recovered",
			);
			expect(recovered.map((e) => [e.subject, e.attributes])).toEqual([
				[
					expect.stringMatching(/./),
					expect.objectContaining({
						operation: "recover",
						generation: "1",
						week: "true",
						run: "true",
						hard: "false",
					}),
				],
			]);
		},
	);

	it("refuses a session no recovery code or passkey let in", async () => {
		const { secret } = await s.enrol("ben");
		const { b, transaction } = await s.held("ben");
		const factor = (await b.factors(transaction)).find((f) => f.kind === "totp");
		const done = await b.send("POST", "/session/mfa/verify", {
			transaction_id: transaction,
			factor_id: factor?.id ?? "",
			proof: totp(secret, 1),
		});
		expect(done.status).toBe(200);
		const answer = await b.send("POST", release);
		expect([answer.status, answer.body]).toEqual([
			403,
			{
				error: "mfa_exempt_proof_required",
				error_description: "Verify a recovery code or a passkey first, then release",
			},
		]);
	});

	it("ends the run of failures when a recovery code lets a login in, so the right TOTP code works again", async () => {
		const { secret, codes } = await s.enrol("fay");
		await guessed(s, "fay", 5);
		await inByRecovery(s, "fay", codes[0] ?? "");
		const { b, transaction } = await s.held("fay");
		const factor = (await b.factors(transaction)).find((f) => f.kind === "totp");
		const answer = await b.send("POST", "/session/mfa/verify", {
			transaction_id: transaction,
			factor_id: factor?.id ?? "",
			proof: totp(secret, 1),
		});
		expect(answer.status).toBe(200);
	});

	it("keeps a hold whose first counted failure the account was not revoked after, and the refusal spends nothing", async () => {
		const { codes } = await s.enrol("cid");
		await guessed(s, "cid", 5);
		const b = await inByRecovery(s, "cid", codes[0] ?? "");
		const answer = await b.send("POST", release);
		expect([answer.status, answer.body]).toEqual([409, refused]);
		const twice = await b.send("POST", release);
		expect([twice.status, twice.body]).toEqual([409, refused]);
	});
});

describe("H. a user's own release of a fixed hold", () => {
	const s = running(
		sceneFor(["dee"], { threshold: 9, backoffSeconds: 1, budget: 10, hardLimit: 10 }),
	);

	it("keeps a fixed hold until its guessable factors are bound again after it, naming when", async () => {
		const began = Date.now();
		const { codes } = await s.enrol("dee");
		await guessed(s, "dee", 9);
		await new Promise((resolve) => setTimeout(resolve, 1100));
		await guessed(s, "dee", 1);
		const b = await inByRecovery(s, "dee", codes[0] ?? "");
		const answer = await b.send("POST", release);
		const { rebind_after: after, ...rest } = answer.body;
		expect([answer.status, rest]).toEqual([409, refused]);
		const at = Date.parse(String(after));
		expect(at).toBeGreaterThanOrEqual(began + 300_000);
		expect(at).toBeLessThanOrEqual(Date.now() + 300_000);
	});
});
