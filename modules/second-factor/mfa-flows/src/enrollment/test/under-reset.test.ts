import { factors } from "@mod/mfa";
import { revocations } from "@mod/subject-revocation";
import { describe, expect, it } from "vitest";
import { clock, during, serve } from "../../../test/harness.ts";

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
	it("shows no recovery codes once a revocation completed after the factor was written, and takes them back", async () => {
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
		expect((await s.app.get(factors).held("uma")).map((f) => f.kind)).toEqual(["code"]);
	});
});
