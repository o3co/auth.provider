import { testRequest } from "@mod/http/testing";
import { defineModule, Unavailable } from "@mod/kernel";
import { bindingProofs } from "@mod/mfa-binding-proof";
import { factorKinds } from "@mod/mfa-extensions";
import { sessions } from "@mod/session";
import { afterEach, expect, it } from "vitest";
import { clock, serve } from "./harness.ts";

/** Whether the binding proof is available at each next ask, then always; each code it sends is kept as sent. */
const contact = { available: [] as boolean[], sent: 0 };
afterEach(() => {
	contact.available = [];
});
const contactProof = defineModule({ name: "edge-proof", replicaSafe: false, takes: [] }, (m) => [
	m.contribute(bindingProofs).by(() => ({
		name: "contact",
		available: async () => contact.available.shift() ?? true,
		send: async () => ({ kind: "sent", show: {}, kept: `e-${++contact.sent}` }),
		check: async (_subject, kept, proof) => proof === kept,
	})),
]);

/** A counting kind that cannot read what it judges while `unreadable`. */
const shy = { unreadable: false };
afterEach(() => {
	shy.unreadable = false;
});
const shyKind = defineModule({ name: "kind-shy", replicaSafe: false, takes: [] }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "shy",
		amr: ["otp"],
		addsSecondFactor: true,
		guessable: true,
		counts: true,
		enroll: async () => ({ secret: "s1", show: {} }),
		verify: async (secret, _state, proof) => {
			if (shy.unreadable) throw new Unavailable("shy");
			return proof === secret
				? { kind: "valid" as const, state: null }
				: { kind: "invalid" as const };
		},
	})),
]);

type Served = Awaited<ReturnType<typeof serve>>;
/** Marks a transaction taken in the store, as another request ending it would. */
const ended = (s: Served, tx: string) => async () => {
	await s.kept.transactions.update(tx, (record) => ({
		value: { ...record, taken: true } as never,
	}));
};
/** A login's first enrollment, its binding proof sent. */
const asked = async (s: Served, subject: string) => {
	const { tx } = await s.heldLogin(subject);
	const enroll = (more: Record<string, string> = {}) =>
		s.call("POST", "/session/mfa/enrollment", { kind: "code", transaction_id: tx, ...more });
	const first = await enroll();
	expect(first.body.error).toBe("mfa_binding_proof_required");
	return { tx, enroll };
};

it("refuses an enrollment without a session, or naming a transaction that is no enrollment's", async () => {
	const s = await serve();
	await s.enrollCode("ada");
	const { tx } = await s.heldLogin("ada");
	const named = await s.call("POST", "/session/mfa/enrollment", {
		kind: "code",
		transaction_id: tx,
	});
	expect([named.status, named.body.error_description]).toEqual([
		400,
		"unknown or expired transaction",
	]);
	const none = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
	expect([none.status, none.body]).toEqual([401, { error: "login_required" }]);
});

it("goes on with a session's enrollment only while the session may change credentials", async () => {
	const s = await serve();
	await s.signIn("bea");
	const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
	clock.shift += 400_000;
	const stale = await s.call("POST", "/session/mfa/enrollment", {
		kind: "code",
		transaction_id: String(begun.body.transaction),
	});
	expect([stale.status, stale.body.error]).toEqual([403, "step_up_required"]);
});

it("answers a subject at the limit of factors 409", async () => {
	const s = await serve({ "max-factors": 2 });
	const { secret } = await s.enrollCode("cid");
	const up = await s.call("POST", "/session/mfa/step-up");
	const tx = String(up.body.transaction);
	const info = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
	const factors = info.body.factors as { id: string; kind: string }[];
	const factor = factors.find((f) => f.kind === "code")?.id ?? "";
	const proof = `${secret}:1`;
	await s.call("POST", "/session/mfa/verify", { transaction_id: tx, factor_id: factor, proof });
	const full = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
	expect([full.status, full.body]).toEqual([409, { error: "mfa_factor_limit" }]);
});

it("refuses a binding mfa asks a proof for once it begins, and begins one whose proof it no longer asks", async () => {
	const s = await serve({}, [contactProof]);
	await s.signIn("dee");
	contact.available = [false, true];
	const late = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
	expect([late.status, late.body]).toEqual([403, { error: "mfa_binding_proof_required" }]);
	contact.available = [true, false, false];
	const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
	expect([begun.status, typeof begun.body.secret]).toEqual([200, "string"]);
});

it("sends the binding proof again for a request with no proof, spending no attempt, and records the login's purpose", async () => {
	const s = await serve({ mode: "required" }, [contactProof]);
	const { tx, enroll } = await asked(s, "eli");
	s.events.length = 0;
	const again = await enroll();
	expect([again.status, again.body.error]).toEqual([403, "mfa_binding_proof_required"]);
	const info = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
	expect(info.body.attempts_remaining).toBe(5);
	expect(s.events.map((e) => e.attributes?.purpose)).toEqual(["enroll-login"]);
});

it("judges no binding proof in a transaction spent meanwhile, and keeps no pass for a challenge replaced meanwhile", async () => {
	const s = await serve({ mode: "required" }, [contactProof]);
	const one = await asked(s, "fay");
	s.kept.beforeNextUpdate(ended(s, one.tx));
	s.events.length = 0;
	expect((await one.enroll({ proof: "wrong" })).status).toBe(400);
	expect(s.events).toEqual([]);
	const two = await asked(s, "gil");
	const proof = `e-${contact.sent}`;
	s.kept.beforeNextUpdate(async () => {
		s.kept.beforeNextUpdate(async () => {
			await s.call("POST", "/session/mfa/challenge", { transaction_id: two.tx });
		});
	});
	expect((await two.enroll({ proof })).status).toBe(400);
});

it("holds no binding proof's challenge in a transaction ended while it was sent", async () => {
	const s = await serve({ mode: "required" }, [contactProof]);
	const { tx } = await s.heldLogin("hal");
	s.kept.beforeNextUpdate(ended(s, tx));
	const sent = await s.call("POST", "/session/mfa/enrollment", {
		kind: "code",
		transaction_id: tx,
	});
	expect(sent.status).toBe(400);
	const other = await asked(s, "ida");
	s.kept.beforeNextUpdate(ended(s, other.tx));
	const again = await s.call("POST", "/session/mfa/challenge", { transaction_id: other.tx });
	expect(again.status).toBe(400);
});

it("answers a completion that lost to another as unknown, and a completion ends the binding", async () => {
	const s = await serve();
	await s.signIn("jo");
	const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
	const tx = String(begun.body.transaction);
	const complete = (proof: string) =>
		s.call("POST", "/session/mfa/enrollment/complete", { transaction_id: tx, proof });
	s.kept.beforeNextUpdate(async () => {
		expect((await complete(`${begun.body.secret}:0`)).status).toBe(200);
	});
	expect((await complete("x:0")).status).toBe(400);
	expect([...s.jar().keys()].some((name) => name.includes("mfa"))).toBe(false);
});

it("answers 503 to a completion whose binding mfa cannot open", async () => {
	const s = await serve();
	await s.signIn("kai");
	const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
	const tx = String(begun.body.transaction);
	await s.kept.transactions.update(tx, (record) => ({
		value: { ...record, held: { pending: "not-sealed" } } as never,
	}));
	expect(
		await s.call("POST", "/session/mfa/enrollment/complete", { transaction_id: tx, proof: "x:0" }),
	).toEqual({ status: 503, body: { error: "temporarily_unavailable" } });
});

it("answers 503 to a completion whose kind cannot read what it judges, spending no attempt", async () => {
	const s = await serve({}, [shyKind]);
	await s.signIn("una");
	const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "shy" });
	const tx = String(begun.body.transaction);
	const complete = () =>
		s.call("POST", "/session/mfa/enrollment/complete", { transaction_id: tx, proof: "s1" });
	shy.unreadable = true;
	expect(await complete()).toEqual({ status: 503, body: { error: "temporarily_unavailable" } });
	const shown = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
	expect(shown.body.attempts_remaining).toBe(5);
	shy.unreadable = false;
	expect((await complete()).status).toBe(200);
});

it("goes on with a session's enrollment after the session is raised, never after it closes", async () => {
	const s = await serve();
	const { secret } = await s.enrollCode("lou");
	let n = 0;
	/** Raises the session by a step-up proving the code factor, in a copy of the browser keeping its own transaction. */
	const raise = async () => {
		const jar = new Map(s.jar());
		const up = await s.call("POST", "/session/mfa/step-up", {}, { jar });
		const tx = String(up.body.transaction);
		const info = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx }, { jar });
		const factor = (info.body.factors as { id: string; kind: string }[])[0]?.id ?? "";
		const proof = `${secret}:${++n}`;
		const body = { transaction_id: tx, factor_id: factor, proof };
		await s.call("POST", "/session/mfa/verify", body, { jar });
		s.jar().set("__Host-session", jar.get("__Host-session") ?? "");
	};
	const begin = async () => {
		await raise();
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		return { tx: String(begun.body.transaction), proof: `${begun.body.secret}:0` };
	};
	const complete = ({ tx, proof }: { tx: string; proof: string }) =>
		s.call("POST", "/session/mfa/enrollment/complete", { transaction_id: tx, proof });
	const raised = await begin();
	const before = s.jar().get("__Host-session");
	await raise();
	expect(s.jar().get("__Host-session")).not.toBe(before);
	expect((await complete(raised)).status).toBe(200);
	const closing = await begin();
	const cookie = `__Host-session=${s.jar().get("__Host-session")}`;
	const session = await s.app
		.get(sessions)
		.enter(testRequest({ headers: new Map([["cookie", cookie]]) }));
	await s.app.get(sessions).close(session?.id ?? "");
	expect(await complete(closing)).toEqual({ status: 401, body: { error: "login_required" } });
});
