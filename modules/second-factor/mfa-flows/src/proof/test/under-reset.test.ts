import { factors } from "@mod/mfa";
import { revocations } from "@mod/subject-revocation";
import { describe, expect, it } from "vitest";
import { clock, serve } from "../../../test/harness.ts";

/** What an operator's reset does to a subject (`mfa-reset`), here without it: both boundaries, and the factors removed between them. */
const resetting = async (s: Awaited<ReturnType<typeof serve>>, subject: string) => {
	await s.app.get(revocations).record(subject, { keepDelegations: true });
	await s.app.get(factors).clear(subject);
	await s.app.get(revocations).record(subject, { keepDelegations: true });
};

describe("a login a reset comes into", () => {
	it("opens no session for a login proved before the second boundary, whenever the session would open", async () => {
		const s = await serve();
		const { secret } = await s.enrollCode("kit");
		const { tx, factor } = await s.heldLogin("kit");
		clock.shift += 1000;
		// The proof passes; the reset runs whole before the take, and the login opens a second later.
		s.kept.beforeNextUpdate(async () => {
			s.kept.beforeNextUpdate(async () => {
				await resetting(s, "kit");
				clock.shift += 1000;
			});
		});
		const proof = { transaction_id: tx, factor_id: factor(), proof: `${secret}:1` };
		const proved = await s.call("POST", "/session/mfa/verify", proof);
		expect([proved.status, proved.body]).toEqual([401, { error: "login_required" }]);
		expect(s.jar().has("__Host-session")).toBe(false);
	});
});
