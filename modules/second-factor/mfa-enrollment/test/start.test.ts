import { defineModule } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { bindingProofs } from "@mod/mfa-binding-proof";
import { type AskedFrom, type Enrolled, factorKinds, type Sending } from "@mod/mfa-extensions";
import { afterEach, expect, it } from "vitest";
import { serve } from "./harness.ts";

/** How the kind and the binding proof answer next; the kind's secret is a value no two factors may hold. */
const next = {
	enrolled: undefined as Enrolled | undefined,
	sent: undefined as Sending | undefined,
};
/** Whom each call of the kind and the binding proof was asked for, in order. */
const froms: (AskedFrom | undefined)[] = [];
afterEach(() => {
	next.enrolled = undefined;
	next.sent = undefined;
	froms.length = 0;
});
const parts = defineModule({ name: "start-parts", takes: [] }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "told",
		amr: ["otp"],
		addsSecondFactor: true,
		guessable: true,
		counts: true,
		uniqueSecret: (factor) => factor.secret,
		enroll: async (_subject, _held, from) => {
			froms.push(from);
			return next.enrolled ?? { secret: "t1", show: {} };
		},
		verify: async (secret, _state, proof) =>
			proof === secret ? { kind: "valid" as const, state: null } : { kind: "invalid" as const },
	})),
	m.contribute(bindingProofs).by(() => ({
		name: "contact",
		available: async (_subject, from) => {
			froms.push(from);
			return next.sent !== undefined;
		},
		send: async (_subject, _until, from) => {
			froms.push(from);
			return next.sent ?? { kind: "limited" };
		},
		check: async (_subject, kept, proof) => proof === kept,
	})),
]);

it("starts a session's enrollment only once a binding begins or its proof is sent, writing nothing for a refusal", async () => {
	const s = await serve({}, [parts]);
	await s.signIn("amy");
	const saved = s.kept.saves.count;
	const saves = () => s.kept.saves.count - saved;
	const enroll = (kind = "told") => s.call("POST", "/session/mfa/enrollment", { kind });
	expect((await enroll("nope")).status).toBe(400);
	next.enrolled = { kind: "limited" };
	expect((await enroll()).status).toBe(429);
	next.enrolled = { kind: "refused" };
	expect((await enroll()).status).toBe(403);
	next.enrolled = undefined;
	next.sent = { kind: "limited" };
	expect((await enroll()).status).toBe(429);
	next.sent = { kind: "refused" };
	expect((await enroll()).status).toBe(403);
	expect(saves()).toBe(0);
	next.sent = { kind: "sent", show: {}, kept: "k1" };
	const asked = await enroll();
	expect([asked.status, typeof asked.body.transaction, saves()]).toEqual([403, "string", 1]);
	const begun = await s.call("POST", "/session/mfa/enrollment", {
		kind: "told",
		transaction_id: String(asked.body.transaction),
		proof: "k1",
	});
	expect([begun.status, begun.body.transaction, saves()]).toEqual([200, asked.body.transaction, 1]);
	const done = await s.call("POST", "/session/mfa/enrollment/complete", {
		transaction_id: String(begun.body.transaction),
		proof: "t1",
	});
	expect(done.status).toBe(200);
});

it("answers a binding whose value another factor holds as a duplicate, spending no attempt", async () => {
	const s = await serve({ mode: "required" }, [parts]);
	const bo = await s.heldLogin("bo");
	const enroll = (tx: string) =>
		s.call("POST", "/session/mfa/enrollment", { kind: "told", transaction_id: tx });
	await enroll(bo.tx);
	const bound = await s.call("POST", "/session/mfa/enrollment/complete", {
		transaction_id: bo.tx,
		proof: "t1",
	});
	expect(bound.status).toBe(200);
	const cy = await s.heldLogin("cy");
	expect(await enroll(cy.tx)).toEqual({ status: 409, body: { error: "mfa_factor_duplicate" } });
	const info = await s.call("GET", "/session/mfa/transaction", { transaction_id: cy.tx });
	expect(info.body.attempts_remaining).toBe(5);
});

it("asks the kind and the binding proof for a session's enrollment by its handle, and a held login's by the login", async () => {
	const s = await serve({ mode: "required" }, [parts]);
	await s.signIn("amy");
	await s.call("POST", "/session/mfa/enrollment", { kind: "told" });
	expect(froms.length).toBeGreaterThan(0);
	expect(froms.every((from) => from?.kind === "session" && typeof from.handle === "string")).toBe(
		true,
	);
	froms.length = 0;
	const bo = await s.heldLogin("bo");
	await s.call("POST", "/session/mfa/enrollment", { kind: "told", transaction_id: bo.tx });
	expect(froms.length).toBeGreaterThan(0);
	expect(froms.every((from) => from?.kind === "login")).toBe(true);
});

it("takes all it names, composed with mfa-flows and mfa", async () => {
	expect(await takesUnused((await serve()).input)).toEqual({});
});
