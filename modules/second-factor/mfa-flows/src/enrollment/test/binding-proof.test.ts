import { testRequest } from "@mod/http/testing";
import { defineModule, Unavailable } from "@mod/kernel";
import { factorKinds, type Sending } from "@mod/mfa";
import { bindingProofs } from "@mod/mfa-binding-proof";
import { sessions } from "@mod/session";
import { afterEach, describe, expect, it } from "vitest";
import { serve } from "../../../test/harness.ts";

/** How the binding proof answers its next send, and whether it can read what it checks; each sent one keeps its own code. */
const contact = { sent: 0, answer: undefined as Sending | undefined, unreadable: false };
/** A binding proof asked of every subject: it sends a code and takes that code back. */
const contactProof = defineModule({ name: "contact-proof" }, (m) => [
	m.contribute(bindingProofs).by(() => ({
		name: "contact",
		available: async () => true,
		send: async () => {
			contact.sent++;
			return contact.answer ?? { kind: "sent", show: { to: "c***" }, kept: `c-${contact.sent}` };
		},
		check: async (_subject, kept, proof) => {
			if (contact.unreadable) throw new Unavailable("contact");
			return proof === kept;
		},
	})),
]);
/** A counting kind that refuses to give a secret while `limited`. */
const told = { limited: false };
const toldKind = defineModule({ name: "kind-told" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "told",
		amr: ["otp"],
		addsSecondFactor: true,
		guessable: true,
		counts: true,
		enroll: async () => (told.limited ? { kind: "limited" as const } : { secret: "t1", show: {} }),
		verify: async () => ({ kind: "invalid" as const }),
	})),
]);
/** A counting kind declaring two amr values, as a WebAuthn one does; a proof adds one. */
const pairKind = defineModule({ name: "kind-pair" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "pair",
		amr: ["hwk", "swk"],
		addsSecondFactor: true,
		guessable: false,
		counts: true,
		enroll: async () => ({ secret: "p1", show: {} }),
		verify: async (secret: string, _state: unknown, proof: string) =>
			proof === secret
				? { kind: "valid" as const, state: null, amr: ["hwk"] }
				: { kind: "invalid" as const },
	})),
]);
afterEach(() => {
	contact.answer = undefined;
	contact.unreadable = false;
	told.limited = false;
});

type Served = Awaited<ReturnType<typeof serve>>;
/** The amr of the browser's session. */
const amrOf = async (s: Served) => {
	const cookie = `__Host-session=${s.jar().get("__Host-session")}`;
	const request = testRequest({ headers: new Map([["cookie", cookie]]) });
	return (await s.app.get(sessions).enter(request))?.context.amr;
};
/** Passes the binding proof in the transaction, then binds a factor of the kind there. */
const boundOnProof = async (s: Served, tx: string, kind = "code") => {
	const enroll = (more: Record<string, string>) =>
		s.call("POST", "/session/mfa/enrollment", { kind, transaction_id: tx, ...more });
	const begun = await enroll({ proof: `c-${contact.sent}` });
	const proof = kind === "code" ? `${begun.body.secret}:0` : "p1";
	return s.call("POST", "/session/mfa/enrollment/complete", { transaction_id: tx, proof });
};

describe("a binding proof before a first factor", () => {
	it("lets a login's first factor bound on it finish that login, adding what the factor proves", async () => {
		const s = await serve({ mode: "required" }, [contactProof]);
		const { tx } = await s.heldLogin("noa");
		await s.call("POST", "/session/mfa/enrollment", { kind: "code", transaction_id: tx });
		const done = await boundOnProof(s, tx);
		expect([done.status, done.body.redirect_to]).toEqual([200, "https://app.example/back"]);
		expect([(done.body.factor as { kind: string }).kind, done.body.recovery_codes]).toEqual([
			"code",
			expect.any(Array),
		]);
		expect(await amrOf(s)).toEqual(["pwd", "otp", "mfa"]);
	});

	it("counts a factor whose kind declares several amr values at once, by the amr its first proof adds", async () => {
		const s = await serve({ mode: "required" }, [contactProof, pairKind]);
		const { tx } = await s.heldLogin("pam");
		await s.call("POST", "/session/mfa/enrollment", { kind: "pair", transaction_id: tx });
		const atLogin = await boundOnProof(s, tx, "pair");
		expect([atLogin.status, atLogin.body.redirect_to]).toEqual([200, "https://app.example/back"]);
		expect(await amrOf(s)).toEqual(["pwd", "hwk", "mfa"]);
		await s.signIn("quin");
		const old = s.jar().get("__Host-session");
		const asked = await s.call("POST", "/session/mfa/enrollment", { kind: "pair" });
		expect((await boundOnProof(s, String(asked.body.transaction), "pair")).status).toBe(200);
		expect(s.jar().get("__Host-session")).not.toBe(old);
		expect(await amrOf(s)).toEqual(["pwd", "hwk", "mfa"]);
	});

	it("raises the session a first factor is bound in on it, which may then change factors", async () => {
		const s = await serve({}, [contactProof]);
		await s.signIn("ora");
		const old = s.jar().get("__Host-session");
		const asked = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		const done = await boundOnProof(s, String(asked.body.transaction));
		expect(done.status).toBe(200);
		expect(s.jar().get("__Host-session")).not.toBe(old);
		expect(await amrOf(s)).toEqual(["pwd", "otp", "mfa"]);
		const factor_id = (done.body.factor as { id: string }).id;
		const renamed = await s.call("POST", "/session/mfa/factors/rename", { factor_id, label: "a" });
		expect(renamed.status).toBe(200);
	});

	it("asks it before a session's first factor begins, counts a wrong one as an attempt, and begins once it passes", async () => {
		const s = await serve({}, [contactProof]);
		await s.signIn("pia");
		const asked = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		expect(asked.status).toBe(403);
		expect(asked.body).toMatchObject({
			error: "mfa_binding_proof_required",
			proof: "contact",
			to: "c***",
		});
		expect(asked.body).not.toHaveProperty("secret");
		const tx = String(asked.body.transaction);
		const enroll = (proof: string) =>
			s.call("POST", "/session/mfa/enrollment", { kind: "code", transaction_id: tx, proof });
		const wrong = await enroll("c-0");
		expect([wrong.status, wrong.body]).toEqual([
			401,
			{ error: "mfa_invalid", attempts_remaining: 4 },
		]);
		const begun = await enroll(`c-${contact.sent}`);
		expect([begun.status, begun.body.transaction, typeof begun.body.secret]).toEqual([
			200,
			tx,
			"string",
		]);
		const done = await s.call("POST", "/session/mfa/enrollment/complete", {
			transaction_id: tx,
			proof: `${begun.body.secret}:0`,
		});
		expect(done.status).toBe(200);
	});

	it("takes a pass once, only for the transaction and the kind it was proved for", async () => {
		const s = await serve({}, [contactProof, toldKind]);
		await s.signIn("rio");
		const start = async () =>
			String((await s.call("POST", "/session/mfa/enrollment", { kind: "code" })).body.transaction);
		const enroll = (tx: string, kind: string, proof?: string) =>
			s.call("POST", "/session/mfa/enrollment", {
				kind,
				transaction_id: tx,
				...(proof === undefined ? {} : { proof }),
			});
		const refused = { status: 403, body: { error: "mfa_binding_proof_required" } };
		const first = await start();
		// Proved for a kind that cannot begin now, the pass is kept for that kind alone.
		told.limited = true;
		expect((await enroll(first, "told", `c-${contact.sent}`)).status).toBe(429);
		told.limited = false;
		const challenged = await s.call("POST", "/session/mfa/challenge", { transaction_id: first });
		expect([challenged.status, challenged.body]).toEqual([200, {}]);
		expect(await enroll(first, "code")).toMatchObject(refused);
		const kept = (await s.kept.transactions.read(first)) as unknown as { bindingPassed: unknown };
		// Carried into another transaction, it begins nothing there.
		const second = await start();
		await s.kept.transactions.update(second, (record) => ({
			value: { ...record, bindingPassed: kept.bindingPassed } as never,
		}));
		expect(await enroll(second, "told")).toEqual(refused);
		// Proved there, it begins once: the binding begun takes it.
		expect((await enroll(second, "code", `c-${contact.sent}`)).status).toBe(200);
		expect(await enroll(second, "code")).toMatchObject(refused);
	});

	it("refuses a kind it cannot bind before any binding proof is sent", async () => {
		const s = await serve({ mode: "required" }, [contactProof]);
		const { tx } = await s.heldLogin("ivy");
		const sent = contact.sent;
		for (const kind of ["none", "backup"]) {
			const refused = await s.call("POST", "/session/mfa/enrollment", { kind, transaction_id: tx });
			expect([refused.status, refused.body.error_description]).toEqual([400, "unknown kind"]);
		}
		expect(contact.sent).toBe(sent);
	});

	it("asks it within a login's first enrollment, and ends the transaction with the last attempt", async () => {
		const s = await serve({ mode: "required", "attempts-per-transaction": 2 }, [contactProof]);
		const { tx } = await s.heldLogin("rae");
		const enroll = (more: Record<string, string> = {}) =>
			s.call("POST", "/session/mfa/enrollment", { kind: "code", transaction_id: tx, ...more });
		const asked = await enroll();
		expect([asked.status, asked.body.error, asked.body.transaction]).toEqual([
			403,
			"mfa_binding_proof_required",
			tx,
		]);
		const proved = await enroll({ proof: `c-${contact.sent}` });
		expect(proved.status).toBe(200);
		const next = await s.heldLogin("sam");
		const other = (more: Record<string, string> = {}) =>
			s.call("POST", "/session/mfa/enrollment", {
				kind: "code",
				transaction_id: next.tx,
				...more,
			});
		await other();
		expect((await other({ proof: "c-0" })).body.attempts_remaining).toBe(1);
		expect((await other({ proof: "c-0" })).body.attempts_remaining).toBe(0);
		expect((await other({ proof: `c-${contact.sent}` })).status).toBe(400);
	});

	it("ends the transaction when it passes on the last attempt, beginning no binding that could not complete", async () => {
		const s = await serve({ mode: "required", "attempts-per-transaction": 2 }, [contactProof]);
		const { tx } = await s.heldLogin("lia");
		const enroll = (more: Record<string, string> = {}) =>
			s.call("POST", "/session/mfa/enrollment", { kind: "code", transaction_id: tx, ...more });
		await enroll();
		expect((await enroll({ proof: "c-0" })).body.attempts_remaining).toBe(1);
		const last = await enroll({ proof: `c-${contact.sent}` });
		expect([last.status, last.body.error_description]).toEqual([
			400,
			"unknown or expired transaction",
		]);
		const ended = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
		expect(ended.status).toBe(400);
	});

	it("sends it again through the challenge route, where only the last one sent passes, and a limited resend leaves it standing", async () => {
		const s = await serve({}, [contactProof]);
		await s.signIn("uma");
		const asked = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		const tx = String(asked.body.transaction);
		const first = contact.sent;
		const challenge = () => s.call("POST", "/session/mfa/challenge", { transaction_id: tx });
		const again = await challenge();
		expect([again.status, again.body]).toEqual([200, { proof: "contact", to: "c***" }]);
		const enroll = (proof: string) =>
			s.call("POST", "/session/mfa/enrollment", { kind: "code", transaction_id: tx, proof });
		expect((await enroll(`c-${first}`)).status).toBe(401);
		contact.answer = { kind: "limited" };
		expect((await challenge()).status).toBe(429);
		contact.answer = undefined;
		expect((await enroll(`c-${first + 1}`)).status).toBe(200);
		// The binding begun took the pass, so a new proof is sent.
		expect((await challenge()).body).toEqual({ proof: "contact", to: "c***" });
	});

	it("records each one sent, each wrong one and the one that passes, by the proof's name, never a code", async () => {
		const s = await serve({}, [contactProof]);
		await s.signIn("eva");
		s.events.length = 0;
		const asked = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		const tx = String(asked.body.transaction);
		const enroll = (proof: string) =>
			s.call("POST", "/session/mfa/enrollment", { kind: "code", transaction_id: tx, proof });
		expect((await enroll("c-0")).status).toBe(401);
		await s.call("POST", "/session/mfa/challenge", { transaction_id: tx });
		expect((await enroll(`c-${contact.sent}`)).status).toBe(200);
		const judged = { kind: "contact", purpose: "enroll", source: "198.51.100.1" };
		expect(s.events.map((e) => [e.kind, e.subject, e.attributes])).toEqual([
			["mfa.challenge.sent", "eva", judged],
			["mfa.verify.failure", "eva", { ...judged, reason: "invalid" }],
			["mfa.challenge.sent", "eva", judged],
			["mfa.verified", "eva", judged],
		]);
		expect(JSON.stringify(s.events)).not.toContain("c-");
	});

	it("answers 503 to a proof it cannot judge, spending no attempt", async () => {
		const s = await serve({}, [contactProof]);
		await s.signIn("ida");
		const asked = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		const tx = String(asked.body.transaction);
		const enroll = () =>
			s.call("POST", "/session/mfa/enrollment", {
				kind: "code",
				transaction_id: tx,
				proof: `c-${contact.sent}`,
			});
		contact.unreadable = true;
		expect(await enroll()).toEqual({ status: 503, body: { error: "temporarily_unavailable" } });
		const shown = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
		expect(shown.body.attempts_remaining).toBe(5);
		contact.unreadable = false;
		expect((await enroll()).status).toBe(200);
	});

	it("answers a proof the sender limits 429, one it cannot give 403, and begins nothing", async () => {
		const s = await serve({}, [contactProof]);
		await s.signIn("tia");
		contact.answer = { kind: "limited" };
		const limited = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		expect([limited.status, limited.body]).toEqual([429, { error: "rate_limited" }]);
		contact.answer = { kind: "refused" };
		const refused = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		expect([refused.status, refused.body]).toEqual([
			403,
			{ error: "mfa_binding_proof_unavailable" },
		]);
	});
});
