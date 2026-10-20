import { expect, it } from "vitest";
import { serve } from "../../../test/harness.ts";

it("holds a login that must bind a first factor in a transaction the enrollment flow binds in", async () => {
	const s = await serve({ mode: "required" });
	const held = await s.login("nina");
	if (held.kind !== "held") throw new Error(held.kind);
	expect(held.answer).toMatchObject({ error: "mfa_enrollment_required" });
	const tx = String((held.answer as { transaction: string }).transaction);
	const begun = await s.call("POST", "/session/mfa/enrollment", {
		kind: "code",
		transaction_id: tx,
	});
	expect([begun.status, begun.body.transaction]).toEqual([200, tx]);
	const done = await s.call("POST", "/session/mfa/enrollment/complete", {
		transaction_id: tx,
		proof: `${begun.body.secret}:0`,
	});
	expect(done.status).toBe(200);
	const again = await s.login("nina");
	expect(again.kind === "held" && again.answer).toMatchObject({ error: "mfa_required" });
});
