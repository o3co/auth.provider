import { contract, defineModule } from "@mod/kernel";
import { factors } from "@mod/mfa";
import { type Enrolled, factorKinds } from "@mod/mfa-extensions";
import { flowParts } from "@mod/mfa-flows";
import { seal } from "@mod/seal";
import { subjectRevocation } from "@mod/subject-revocation";
import { afterEach, describe, expect, it } from "vitest";
import { holding } from "../src/held.ts";
import { clock, serve } from "./harness.ts";

/** A kind that sends a challenge, and takes what the challenge kept as the proof after it. */
const _sending = defineModule({ name: "kind-sending" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "sending",
		amr: ["otp"],
		addsSecondFactor: true,
		guessable: true,
		counts: true,
		enroll: async () => ({ secret: "first", show: {} }),
		challenge: async () => ({ kind: "sent" as const, show: { to: "a***" }, kept: "sent-code" }),
		verify: async (secret, _state, proof, kept) =>
			proof === (kept ?? secret)
				? { kind: "valid" as const, state: null }
				: { kind: "invalid" as const },
	})),
]);

/** How the told kind answers its next enrollment; its secret is the value no two factors may hold. */
const told = { answer: undefined as Enrolled | undefined };
const toldKind = defineModule({ name: "kind-told" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "told",
		amr: ["otp"],
		addsSecondFactor: true,
		guessable: true,
		counts: true,
		uniqueSecret: (factor) => factor.secret,
		enroll: async () => told.answer ?? { secret: "t1", show: {} },
		verify: async (secret, _state, proof) =>
			proof === secret ? { kind: "valid" as const, state: null } : { kind: "invalid" as const },
	})),
]);
afterEach(() => {
	told.answer = undefined;
});

/** The identifier of the factor of this kind, in an answer listing factors. */
const _idOf = (listed: { body: Record<string, unknown> }, kind: string) =>
	(listed.body.factors as { id: string; kind: string }[]).find((f) => f.kind === kind)?.id ?? "";

describe("mfa at login", () => {
	it("ends a login's first binding once the subject was revoked since, and shows it to no one", async () => {
		const s = await serve({ mode: "required" });
		const { tx } = await s.heldLogin("carol");
		clock.shift += 2000;
		await s.app.get(subjectRevocation).revoke("carol");
		clock.shift += 40_000;
		const shown = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
		expect([shown.status, shown.body.error]).toEqual([401, "login_required"]);
		const begun = await s.call("POST", "/session/mfa/enrollment", {
			kind: "code",
			transaction_id: tx,
		});
		expect([begun.status, begun.body.error]).toEqual([401, "login_required"]);
		const ended = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
		expect(ended.status).toBe(400);
	});

	it("asks a first binding under required mode, which counts from the next sign-in, not this one", async () => {
		const s = await serve({ mode: "required" });
		const held = await s.login("carol");
		expect(held.kind === "held" && held.answer).toMatchObject({ error: "mfa_enrollment_required" });
		const { tx } = await s.heldLogin("carol");
		const begun = await s.call("POST", "/session/mfa/enrollment", {
			kind: "code",
			transaction_id: tx,
		});
		const done = await s.call("POST", "/session/mfa/enrollment/complete", {
			transaction_id: tx,
			proof: `${begun.body.secret}:0`,
		});
		expect(done.status).toBe(200);
		expect(done.body).toHaveProperty("factor");
		expect(done.body).not.toHaveProperty("next");
		expect(s.jar().has("__Host-session")).toBe(false);
		const again = await s.login("carol");
		expect(again.kind === "held" && again.answer).toMatchObject({ error: "mfa_required" });
		const next = await s.heldLogin("carol");
		const proved = await s.call("POST", "/session/mfa/verify", {
			transaction_id: next.tx,
			factor_id: next.factor(),
			proof: `${begun.body.secret}:1`,
		});
		expect(proved.status).toBe(200);
		expect(s.jar().has("__Host-session")).toBe(true);
	});
});

describe("transactions on the kernel's clock", () => {
	it("binds once when another request completes the same enrollment first", async () => {
		const s = await serve();
		await s.signIn("dot");
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		const own = s.jar();
		const complete = () =>
			s.call(
				"POST",
				"/session/mfa/enrollment/complete",
				{ transaction_id: String(begun.body.transaction), proof: `${begun.body.secret}:0` },
				{ jar: new Map(own) },
			);
		// Skips this one's spend; the other completion runs whole just before its take.
		let other: Awaited<ReturnType<typeof complete>> | undefined;
		s.kept.beforeNextUpdate(async () => {
			s.kept.beforeNextUpdate(async () => {
				other = await complete();
			});
		});
		const late = await complete();
		expect([other?.status, late.status]).toEqual([200, 400]);
	});

	it("holds no binding in a login's transaction whose lifetime ends before the hold writes", async () => {
		const s = await serve({ mode: "required", "transaction-lifetime": "1m" });
		const { tx } = await s.heldLogin("carol");
		s.kept.beforeNextUpdate(async () => {
			clock.shift += 60_000;
		});
		const begun = await s.call("POST", "/session/mfa/enrollment", {
			kind: "code",
			transaction_id: tx,
		});
		expect(begun.status).toBe(400);
	});
});

describe("mfa in a session", () => {
	it("goes on with a session's enrollment only in that session", async () => {
		const s = await serve();
		await s.signIn("val");
		const mine = new Map(s.jar());
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" }, { jar: mine });
		const tx = String(begun.body.transaction);
		await s.signIn("val");
		const swapped = new Map(mine);
		swapped.set("__Host-session", s.jar().get("__Host-session") ?? "");
		const without = new Map(mine);
		without.delete("__Host-session");
		for (const jar of [swapped, without]) {
			const refused = [
				await s.call(
					"POST",
					"/session/mfa/enrollment",
					{ kind: "code", transaction_id: tx },
					{ jar },
				),
				await s.call("POST", "/session/mfa/challenge", { transaction_id: tx }, { jar }),
				await s.call(
					"POST",
					"/session/mfa/enrollment/complete",
					{ transaction_id: tx, proof: `${begun.body.secret}:0` },
					{ jar },
				),
			];
			expect(refused.map((r) => [r.status, r.body.error])).toEqual([
				[401, "login_required"],
				[401, "login_required"],
				[401, "login_required"],
			]);
		}
		const done = await s.call(
			"POST",
			"/session/mfa/enrollment/complete",
			{ transaction_id: tx, proof: `${begun.body.secret}:0` },
			{ jar: mine },
		);
		expect(done.status).toBe(200);
	});

	it("answers a kind's limited enrollment 429, a refused one 403, and a value another factor holds 409", async () => {
		const s = await serve({}, [toldKind]);
		const enroll = () => s.call("POST", "/session/mfa/enrollment", { kind: "told" });
		const complete = (tx: unknown, jar: Map<string, string>) =>
			s.call(
				"POST",
				"/session/mfa/enrollment/complete",
				{ transaction_id: String(tx), proof: "t1" },
				{ jar },
			);
		await s.signIn("ola");
		told.answer = { kind: "limited" };
		expect(await enroll()).toEqual({ status: 429, body: { error: "rate_limited" } });
		told.answer = { kind: "refused" };
		expect(await enroll()).toEqual({ status: 403, body: { error: "mfa_factor_refused" } });
		told.answer = undefined;
		const [first, ola] = [await enroll(), s.jar()];
		await s.signIn("pat");
		expect((await complete((await enroll()).body.transaction, s.jar())).status).toBe(200);
		const late = await complete(first.body.transaction, ola);
		expect(late).toEqual({ status: 409, body: { error: "mfa_factor_duplicate" } });
		await s.signIn("ola");
		expect(await enroll()).toEqual({ status: 409, body: { error: "mfa_factor_duplicate" } });
	});
});

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
/** Slow kinds, so concurrent requests all read before any of them writes. */
const verifies = { guess: 0 };
afterEach(() => {
	verifies.guess = 0;
});
const slowOnce = defineModule({ name: "kind-slow-once" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "once",
		amr: ["hwk"],
		addsSecondFactor: true,
		guessable: false,
		counts: true,
		enroll: async () => {
			const codes = ["o1", "o2", "o3"];
			return { secret: JSON.stringify(codes), show: { codes } };
		},
		verify: async (secret, state, proof) => {
			await pause(50);
			const used = Array.isArray(state) ? (state as string[]) : [];
			if (!(JSON.parse(secret) as string[]).includes(proof)) return { kind: "invalid" as const };
			return used.includes(proof)
				? { kind: "replayed" as const }
				: { kind: "valid" as const, state: [...used, proof] };
		},
	})),
]);
const _slowGuess = defineModule({ name: "kind-slow-guess" }, (m) => [
	m.contribute(factorKinds).by(() => ({
		kind: "guess",
		amr: ["otp"],
		addsSecondFactor: true,
		guessable: true,
		counts: true,
		enroll: async () => ({ secret: "g", show: { secret: "g" } }),
		verify: async (_secret, _state, proof) => {
			verifies.guess++;
			await pause(50);
			return proof === "g" ? { kind: "valid" as const, state: null } : { kind: "invalid" as const };
		},
	})),
]);

describe("mfa under races and misuse", () => {
	const _enroll = async (
		s: Awaited<ReturnType<typeof serve>>,
		subject: string,
		kind: string,
		proof: string,
	) => {
		await s.signIn(subject);
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind });
		return s.call("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof,
		});
	};

	it("refuses to finish an enrollment started before the subject was revoked", async () => {
		const s = await serve();
		await s.signIn("rex");
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		clock.shift += 2000;
		await s.app.get(subjectRevocation).revoke("rex");
		clock.shift += 40_000;
		// Revocation is judged before the label.
		const done = await s.call(
			"POST",
			"/session/mfa/enrollment/complete",
			{ transaction_id: String(begun.body.transaction), proof: `${begun.body.secret}:0`, label: 5 },
			{ json: true },
		);
		expect([done.status, done.body.error]).toEqual([401, "login_required"]);
		const ended = await s.call("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: `${begun.body.secret}:0`,
		});
		expect(ended.status).toBe(400);
	});

	it("hands out one set of recovery codes when two first enrollments finish at once", async () => {
		const s = await serve({}, [slowOnce]);
		await s.signIn("ray");
		const jar = new Map(s.jar());
		const other = new Map(s.jar());
		const begin = (own: Map<string, string>) =>
			s.call("POST", "/session/mfa/enrollment", { kind: "once" }, { jar: own });
		const [first, second] = [await begin(jar), await begin(other)];
		const complete = (begun: typeof first, own: Map<string, string>) =>
			s.call(
				"POST",
				"/session/mfa/enrollment/complete",
				{ transaction_id: String(begun.body.transaction), proof: "o1" },
				{ jar: own },
			);
		const done = await Promise.all([complete(first, jar), complete(second, other)]);
		expect(done.filter((d) => d.body.recovery_codes)).toHaveLength(1);
		// Both began as the first; the one beaten binds nothing, and the session is told of the conflict.
		expect(done.map((d) => [d.status, d.body.error]).sort()).toEqual([
			[200, undefined],
			[409, "mfa_enrollment_conflict"],
		]);
		const held = await s.app.get(factors).held("ray");
		expect(held.filter((f) => f.kind === "backup")).toHaveLength(1);
	});

	it("asks a login again when another factor was bound while its first binding was under way", async () => {
		const s = await serve({ mode: "required" });
		const { tx } = await s.heldLogin("lou");
		const begun = await s.call("POST", "/session/mfa/enrollment", {
			kind: "code",
			transaction_id: tx,
		});
		const held = new Map(s.jar());
		await s.enrollCode("lou");
		const done = await s.call(
			"POST",
			"/session/mfa/enrollment/complete",
			{ transaction_id: tx, proof: `${begun.body.secret}:0` },
			{ jar: held },
		);
		expect([done.status, done.body.error]).toEqual([401, "login_required"]);
		const kept = await s.app.get(factors).held("lou");
		expect(kept.filter((f) => f.kind === "code")).toHaveLength(1);
	});

	it("binds nothing from a login's first binding begun after another factor was bound, on the password alone", async () => {
		const s = await serve({ mode: "required" });
		// Taken while the subject held no factor: the transaction allows a first binding alone.
		const { tx } = await s.heldLogin("lou");
		const held = new Map(s.jar());
		await s.enrollCode("lou");
		const begun = await s.call(
			"POST",
			"/session/mfa/enrollment",
			{ kind: "code", transaction_id: tx },
			{ jar: held },
		);
		expect([begun.status, begun.body.error]).toEqual([401, "login_required"]);
		const done = await s.call(
			"POST",
			"/session/mfa/enrollment/complete",
			{ transaction_id: tx, proof: `${begun.body.secret}:0` },
			{ jar: held },
		);
		// The start held no pending, so there is nothing to complete.
		expect([done.status, done.body.error]).toEqual([400, "invalid_request"]);
		const kept = await s.app.get(factors).held("lou");
		expect(kept.filter((f) => f.kind === "code")).toHaveLength(1);
	});

	it("binds nothing from a login's pending sealed before mfa was told logins, once another factor counts", async () => {
		/** Holds a pending in a transaction, as one sealed by an earlier release, without its first mark. */
		const forging =
			contract<(tx: string, subject: string, secret: string) => Promise<boolean>>("test.forging");
		const forger = defineModule({ name: "forger" }, (m) => [
			m.provide(forging).by(async (c) => {
				const sealed = await c.get(seal);
				const held = (await c.get(flowParts)).transactions;
				return (tx, subject, secret) =>
					holding(held).hold(
						tx,
						sealed.seal(JSON.stringify({ kind: "code", secret }), `${subject}\npending`),
					);
			}),
		]);
		const s = await serve({ mode: "required" }, [forger]);
		const { tx } = await s.heldLogin("lou");
		const held = new Map(s.jar());
		await s.enrollCode("lou");
		expect(await s.app.get(forging)(tx, "lou", "forged")).toBe(true);
		const done = await s.call(
			"POST",
			"/session/mfa/enrollment/complete",
			{ transaction_id: tx, proof: "forged:0" },
			{ jar: held },
		);
		expect([done.status, done.body.error]).toEqual([401, "login_required"]);
		const kept = await s.app.get(factors).held("lou");
		expect(kept.filter((f) => f.kind === "code")).toHaveLength(1);
	});
});

describe("mfa bodies", () => {
	const json = { json: true };

	it("refuses a label that is not a string or not of mfa's shape after the transaction checks and before the proof, and binds none when there is no label", async () => {
		const s = await serve();
		await s.signIn("nina");
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" }, json);
		const tx = String(begun.body.transaction);
		const complete = (body: Record<string, unknown>, how = {}) =>
			s.call("POST", "/session/mfa/enrollment/complete", body, { ...json, ...how });
		const unknown = await complete({ transaction_id: `${tx}x`, proof: "x:0", label: 5 });
		expect([unknown.status, unknown.body.error_description]).toEqual([
			400,
			"unknown or expired transaction",
		]);
		for (const label of [null, 5, { name: "phone" }, ["phone"], "", "ph\none", "\u202ephone"]) {
			const odd = await complete({ transaction_id: tx, proof: "x:0", label });
			expect([label, odd.status, odd.body]).toEqual([
				label,
				400,
				{ error: "invalid_request", error_description: "invalid label" },
			]);
		}
		const emptyForm = await s.call("POST", "/session/mfa/enrollment/complete", {
			transaction_id: tx,
			proof: "x:0",
			label: "",
		});
		expect([emptyForm.status, emptyForm.body.error_description]).toEqual([400, "invalid label"]);
		const info = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
		expect(info.body.attempts_remaining).toBe(5);
		// A transaction_id that is not a string is none, so the header names the transaction.
		const done = await complete(
			{ transaction_id: 7, proof: `${begun.body.secret}:0` },
			{ headers: { "mfa-transaction": tx } },
		);
		expect([done.status, (done.body.factor as { label?: string }).label]).toEqual([200, undefined]);
		const held = await s.app.get(factors).held("nina");
		expect(held.filter((f) => "label" in f)).toEqual([]);
		const up = await s.call("POST", "/session/mfa/step-up", {}, json);
		const pendingless = await complete({
			transaction_id: String(up.body.transaction),
			proof: "x:0",
			label: 5,
		});
		expect([pendingless.status, pendingless.body.error_description]).toEqual([
			400,
			"unknown or expired transaction",
		]);
	});

	it("enrolls in a login by the header's transaction, and never in the session when the two differ", async () => {
		const s = await serve({ mode: "required" });
		await s.signIn("max");
		const session = s.jar().get("__Host-session") ?? "";
		const { tx } = await s.heldLogin("max");
		s.jar().set("__Host-session", session);
		const header = { headers: { "mfa-transaction": tx } };
		const differ = await s.call(
			"POST",
			"/session/mfa/enrollment",
			{ kind: "code", transaction_id: `${tx}x` },
			header,
		);
		expect([differ.status, differ.body.error]).toEqual([400, "invalid_request"]);
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" }, header);
		expect(begun.body.transaction).toBe(tx);
		const done = await s.call(
			"POST",
			"/session/mfa/enrollment/complete",
			{ proof: `${begun.body.secret}:0` },
			header,
		);
		expect(done.status).toBe(200);
	});
});
