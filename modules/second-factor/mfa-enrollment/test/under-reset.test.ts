import { factors } from "@mod/mfa";
import { revocations } from "@mod/subject-revocation";
import { describe, expect, it } from "vitest";
import { clock, during, serve, takingTheCodesPlace, transactionCookie } from "./harness.ts";

/** What an operator's reset does to a subject (`mfa-reset`), here without it: both boundaries, and the factors removed between them. */
const resetting = async (s: Awaited<ReturnType<typeof serve>>, subject: string) => {
	await s.app.get(revocations).record(subject, { keepDelegations: true });
	await s.app.get(factors).clear(subject);
	await s.app.get(revocations).record(subject, { keepDelegations: true });
};

describe("a binding a reset or a revocation comes into", () => {
	it("binds no factor whose enrollment a reset or a revocation came into while its proof was judged", async () => {
		const s = await serve();
		const enrolling = async (subject: string, meanwhile: () => Promise<unknown>) => {
			await s.signIn(subject);
			const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
			clock.shift += 1000;
			during.code = async () => {
				await meanwhile();
				clock.shift += 1000;
			};
			return s.call("POST", "/session/mfa/enrollment/complete", {
				transaction_id: String(begun.body.transaction),
				proof: `${begun.body.secret}:0`,
			});
		};
		const reset = await enrolling("max", () => resetting(s, "max"));
		expect([reset.status, reset.body]).toEqual([401, { error: "login_required" }]);
		expect(await s.app.get(factors).held("max")).toEqual([]);
		const revoked = await enrolling("nia", () => s.app.get(revocations).record("nia"));
		expect([revoked.status, revoked.body]).toEqual([401, { error: "login_required" }]);
		expect(await s.app.get(factors).held("nia")).toEqual([]);
	});
	it("leaves the codes unseen, answering 401, where a revocation lands after the reissue wrote them and before the last check", async () => {
		const s = await serve();
		await s.signIn("ula");
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		clock.shift += 1000;
		// The revocation lands once a write holds the codes: the reissue's, after the bind's.
		const onceWritten = async () => {
			const held = await s.app.get(factors).held("ula");
			if (!held.some((f) => f.kind === "backup")) {
				during.written = onceWritten;
				return;
			}
			await s.app.get(revocations).record("ula");
			clock.shift += 1000;
		};
		during.code = async () => {
			during.written = onceWritten;
		};
		const done = await s.call("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: `${begun.body.secret}:0`,
		});
		expect([done.status, done.body]).toEqual([401, { error: "login_required" }]);
		// Written and seen by no one: a reset clears them, and the subject can reissue them.
		expect((await s.app.get(factors).held("ula")).map((f) => f.kind)).toEqual(["code", "backup"]);
	});

	it("answers 409 clearing the transaction where another factor took the codes' place in a binding on the password alone", async () => {
		const s = await serve({ "max-factors": 2 });
		await s.signIn("una");
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		expect(transactionCookie(s.jar())).toBeDefined();
		takingTheCodesPlace();
		const done = await s.call("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: `${begun.body.secret}:0`,
		});
		expect([done.status, done.body, transactionCookie(s.jar())]).toEqual([
			409,
			{ error: "mfa_factor_limit" },
			undefined,
		]);
	});

	it("writes no recovery codes when a revocation's record lands before its followers fence the binding", async () => {
		const s = await serve();
		await s.signIn("uma");
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		clock.shift += 1000;
		let release = () => {};
		const reached = new Promise<void>((arrived) => {
			during.follow = () => {
				arrived();
				return new Promise<void>((go) => {
					release = go;
				});
			};
		});
		let recorded: Promise<unknown> = Promise.resolve();
		during.code = async () => {
			// After the proof is judged, the bind's write is the next: the revocation's record lands as
			// it answers, and mfa's fence waits behind it, so the factor stands.
			during.written = async () => {
				recorded = s.app.get(revocations).record("uma");
				await reached;
				clock.shift += 1000;
			};
		};
		const done = await s.call("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: `${begun.body.secret}:0`,
		});
		release();
		await recorded;
		expect([done.status, done.body.error, done.body.recovery_codes]).toEqual([
			401,
			"login_required",
			undefined,
		]);
		expect((await s.app.get(factors).held("uma")).map((f) => f.kind)).toEqual(["code"]);
		expect(s.events.some((e) => e.kind === "mfa.recovery_codes.generated")).toBe(false);
	});

	it("writes no factor and no recovery codes once a revocation completes as the binding is written", async () => {
		const s = await serve();
		await s.signIn("uma");
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		clock.shift += 1000;
		during.code = async () => {
			// After the proof is judged, the bind's write is the next: the revocation lands as it answers.
			during.written = async () => {
				await s.app.get(revocations).record("uma");
				clock.shift += 1000;
			};
		};
		const done = await s.call("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: `${begun.body.secret}:0`,
		});
		expect([done.status, done.body.error, done.body.recovery_codes]).toEqual([
			401,
			"login_required",
			undefined,
		]);
		// mfa-revocation moves the fence as the revocation completes, so the write is fenced.
		expect((await s.app.get(factors).held("uma")).map((f) => f.kind)).toEqual([]);
		expect(s.events.some((e) => e.kind === "mfa.recovery_codes.generated")).toBe(false);
	});
});
