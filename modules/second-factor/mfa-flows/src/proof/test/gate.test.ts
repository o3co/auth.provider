import { testRequest } from "@mod/http/testing";
import { logins } from "@mod/login-gates";
import { secondFactorAmr } from "@mod/mfa-extensions";
import { describe, expect, it } from "vitest";
import { serve } from "../../../test/harness.ts";
import type { Transactions } from "../../transactions/transactions.ts";
import { gateOver } from "../proof.ts";

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

describe("a login whose amr holds the second factor already", () => {
	const loginWith = async (s: Awaited<ReturnType<typeof serve>>, subject: string, amr: string[]) =>
		s.app
			.get(logins)
			.login(testRequest(), { subject, amr, authenticatedAt: Date.now() }, { redirect_to: "/" });

	it("opens past the gate, a factor of its subject's never asked for", async () => {
		const s = await serve({});
		await s.enrollCode("ola");
		expect((await loginWith(s, "ola", ["pwd"])).kind).toBe("held");
		expect((await loginWith(s, "ola", ["pop", secondFactorAmr])).kind).toBe("opened");
	});

	it("opens where a first factor is required and its subject has none to bind", async () => {
		const s = await serve({ mode: "required" });
		expect((await loginWith(s, "nina", ["pwd"])).kind).toBe("held");
		expect((await loginWith(s, "nina", ["pop", secondFactorAmr])).kind).toBe("opened");
	});

	it("is held as any other where the amr holds only something like it", async () => {
		const s = await serve({});
		await s.enrollCode("ola");
		for (const like of ["MFA", " mfa", "mfa ", "mfa2"]) {
			expect((await loginWith(s, "ola", ["pwd", like])).kind).toBe("held");
		}
	});

	it("asks nothing of the subject's factors, and starts no transaction", async () => {
		let asked = 0;
		let started = 0;
		const hold = gateOver({
			factors: {
				asks: async () => {
					asked += 1;
					return "proof";
				},
			},
			transactions: {
				start: async () => {
					started += 1;
					throw new Error("no transaction is started");
				},
			} as unknown as Transactions,
		});
		const facts = { subject: "ola", amr: ["pop", secondFactorAmr], authenticatedAt: 1 };
		expect(await hold(testRequest(), facts, undefined, undefined)).toEqual({ kind: "pass" });
		expect([asked, started]).toEqual([0, 0]);
	});
});
