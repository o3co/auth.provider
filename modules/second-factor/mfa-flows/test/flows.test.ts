import { cookies } from "@mod/cookies";
import { listening } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { BootRefused, contract, defineModule } from "@mod/kernel";
import { openedAfterHold } from "@mod/login-gates";
import { type Enrolled, factorKinds, factors } from "@mod/mfa";
import { seal } from "@mod/seal";
import { sessions } from "@mod/session";
import { subjectRevocation } from "@mod/subject-revocation";
import { afterEach, describe, expect, it } from "vitest";
import { transactionListings, transactionStore } from "../src/store.ts";
import {
	type HeldFacts,
	stored,
	type Transaction,
	transactionOf,
} from "../src/transactions/records.ts";
import { transactionsOver } from "../src/transactions/transactions.ts";
import { clock, during, serve } from "./harness.ts";

/** A kind that sends a challenge, and takes what the challenge kept as the proof after it. */
const sending = defineModule({ name: "kind-sending" }, (m) => [
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
const idOf = (listed: { body: Record<string, unknown> }, kind: string) =>
	(listed.body.factors as { id: string; kind: string }[]).find((f) => f.kind === kind)?.id ?? "";

it("refuses a POST without same-origin evidence before anything else", async () => {
	const s = await serve();
	await s.signIn();
	const port = s.app.get(listening).port();
	const res = await fetch(`http://127.0.0.1:${port}/session/mfa/verify`, {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-proto": "https" },
		body: new URLSearchParams({ transaction_id: "x", proof: "y" }),
	});
	expect([res.status, await res.json()]).toEqual([403, { error: "csrf" }]);
});

it("limits the forms it takes per source, after the same-origin check, and never its pages", async () => {
	const { call, signIn, heldLogin } = await serve({ requests: 2, window: "1m", mode: "required" });
	const held = await heldLogin();
	await signIn();
	const crossSite = { headers: { origin: "https://elsewhere.example" } };
	for (let i = 0; i < 2; i++) {
		expect((await call("POST", "/session/mfa/step-up", {}, crossSite)).status).toBe(403);
	}
	for (let i = 0; i < 2; i++) {
		expect((await call("POST", "/session/mfa/step-up", {})).status).not.toBe(429);
	}
	const limited = await call("POST", "/session/mfa/enrollment", { kind: "code" });
	expect([limited.status, limited.body]).toEqual([429, { error: "rate_limited" }]);
	const page = await call(
		"GET",
		"/session/mfa/transaction",
		{ transaction_id: held.tx },
		{ jar: held.jar },
	);
	expect(page.status).toBe(200);
});

describe("mfa at login", () => {
	it("lets a login without factors through, and holds one with a factor until the factor is proved", async () => {
		const s = await serve();
		expect((await s.login("bob")).kind).toBe("opened");
		const { secret, done } = await s.enrollCode();
		expect(done.status).toBe(200);
		expect(done.body.recovery_codes).toHaveLength(2);
		const held = await s.login();
		expect(held.kind === "held" && held.answer).toMatchObject({ error: "mfa_required" });
		const { tx, factor } = await s.heldLogin();
		const verify = (proof: string) =>
			s.call("POST", "/session/mfa/verify", { transaction_id: tx, factor_id: factor(), proof });
		const wrong = await verify("x:1");
		expect([wrong.status, wrong.body]).toEqual([
			401,
			{ error: "mfa_invalid", attempts_remaining: 4 },
		]);
		const right = await verify(`${secret}:1`);
		expect([right.status, right.body]).toEqual([200, { redirect_to: "https://app.example/back" }]);
		expect(s.jar().has("__Host-session")).toBe(true);
		expect((await verify(`${secret}:2`)).status).toBe(400);
	});

	it("answers a transaction from another browser as unknown and spends nothing", async () => {
		const s = await serve();
		const { secret } = await s.enrollCode();
		const { tx, jar: mine, factor } = await s.heldLogin();
		await s.login();
		const foreign = await s.call("POST", "/session/mfa/verify", {
			transaction_id: tx,
			factor_id: factor(),
			proof: `${secret}:1`,
		});
		expect(foreign.status).toBe(400);
		const info = await s.call(
			"GET",
			"/session/mfa/transaction",
			{ transaction_id: tx },
			{ jar: mine },
		);
		expect(info.body.attempts_remaining).toBe(5);
	});

	it("holds a subject after repeated failures even for the right proof, but a way back works and ends the run", async () => {
		const s = await serve({
			lockout: { threshold: 2, backoff: "15m", budget: 10, "hard-limit": 100 },
		});
		const { secret, done } = await s.enrollCode();
		const codes = done.body.recovery_codes as string[];
		for (let i = 0; i < 2; i++) {
			const { tx, factor } = await s.heldLogin();
			await s.call("POST", "/session/mfa/verify", {
				transaction_id: tx,
				factor_id: factor(),
				proof: "x:1",
			});
		}
		const { tx, factor } = await s.heldLogin();
		const locked = await s.call("POST", "/session/mfa/verify", {
			transaction_id: tx,
			factor_id: factor(),
			proof: `${secret}:5`,
		});
		expect([locked.status, locked.body.error]).toEqual([429, "mfa_locked"]);
		const back = await s.call("POST", "/session/mfa/verify", {
			transaction_id: tx,
			factor_id: factor("backup"),
			proof: codes[0] ?? "",
		});
		expect(back.status).toBe(200);
		// A way back ends the run of failures, so the right code works again.
		const next = await s.heldLogin();
		const right = await s.call("POST", "/session/mfa/verify", {
			transaction_id: next.tx,
			factor_id: next.factor(),
			proof: `${secret}:6`,
		});
		expect(right.status).toBe(200);
	});

	it("tells the caller a login came from once the proof opens it, and no one for a login from nowhere", async () => {
		const told: [string, string][] = [];
		const upstream = defineModule({ name: "upstream-stand-in" }, (m) => [
			m.contribute(openedAfterHold).by(() => ({
				caller: "upstream",
				opened: async (session, carry) => void told.push([session.context.subject, carry]),
			})),
		]);
		const s = await serve({}, [upstream]);
		const { secret } = await s.enrollCode();
		const verify = ({ tx, factor }: Awaited<ReturnType<typeof s.heldLogin>>, n: number) =>
			s.call("POST", "/session/mfa/verify", {
				transaction_id: tx,
				factor_id: factor(),
				proof: `${secret}:${n}`,
			});
		const from = await s.heldLogin("alice", { caller: "upstream", carry: "sealed-tokens" });
		expect((await verify(from, 1)).status).toBe(200);
		expect((await verify(await s.heldLogin(), 2)).status).toBe(200);
		expect(told).toEqual([["alice", "sealed-tokens"]]);
	});

	it("opens a login held without an authentication time with the time unknown, and one held with it known", async () => {
		const s = await serve();
		const { secret } = await s.enrollCode();
		const opened = async (n: number, old: boolean) => {
			const { tx, factor } = await s.heldLogin();
			// As a transaction held before the authentication time was reported.
			if (old) {
				await s.kept.transactions.update(tx, (record) => {
					const t = transactionOf(record) as Transaction & {
						readonly purpose: "login";
						readonly facts: HeldFacts;
					};
					const { authenticatedAt: _, ...facts } = t.facts;
					return { value: stored({ ...t, facts }) };
				});
			}
			const proof = `${secret}:${n}`;
			const right = await s.call("POST", "/session/mfa/verify", {
				transaction_id: tx,
				factor_id: factor(),
				proof,
			});
			expect(right.status).toBe(200);
			const cookie = `__Host-session=${s.jar().get("__Host-session") ?? ""}`;
			const request = testRequest({ headers: new Map([["cookie", cookie]]) });
			return (await s.app.get(sessions).enter(request))?.context;
		};
		expect((await opened(1, true))?.authenticatedAtUnknown).toBe(true);
		expect((await opened(2, false))?.authenticatedAtUnknown).toBeUndefined();
	});

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

	it("sends a factor's challenge through mfa, and judges the next proof by what it kept", async () => {
		const s = await serve({}, [sending]);
		await s.signIn("sia");
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "sending" });
		const bound = await s.call("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: "first",
		});
		expect(bound.status).toBe(200);
		const { tx, factor } = await s.heldLogin("sia");
		const challenged = await s.call("POST", "/session/mfa/challenge", {
			transaction_id: tx,
			factor_id: factor("sending"),
		});
		expect([challenged.status, challenged.body]).toEqual([200, { to: "a***" }]);
		const proved = await s.call("POST", "/session/mfa/verify", {
			transaction_id: tx,
			factor_id: factor("sending"),
			proof: "sent-code",
		});
		expect(proved.status).toBe(200);
	});

	it("answers a challenge for a factor whose kind sends none with nothing, and an unknown factor as unknown", async () => {
		const s = await serve();
		await s.enrollCode();
		const { tx, factor } = await s.heldLogin();
		const challenge = (id: string) =>
			s.call("POST", "/session/mfa/challenge", { transaction_id: tx, factor_id: id });
		const none = await challenge(factor());
		expect([none.status, none.body]).toEqual([200, {}]);
		const unknown = await challenge("none");
		expect([unknown.status, unknown.body.error_description]).toEqual([400, "unknown factor"]);
	});

	it("answers 503 when the store fails, and login_required when the subject was revoked since", async () => {
		const s = await serve();
		const { secret } = await s.enrollCode();
		const { tx, factor } = await s.heldLogin();
		const verify = () =>
			s.call("POST", "/session/mfa/verify", {
				transaction_id: tx,
				factor_id: factor(),
				proof: `${secret}:1`,
			});
		s.simulated.unreachable(true);
		const down = await verify();
		s.simulated.unreachable(false);
		expect(down.status).toBe(503);
		s.kept.down.failNext("update");
		expect((await verify()).status).toBe(503);
		clock.shift += 2000;
		await s.app.get(subjectRevocation).revoke("alice");
		clock.shift += 40_000;
		const shown = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
		expect([shown.status, shown.body.error]).toEqual([401, "login_required"]);
		const revoked = await verify();
		expect([revoked.status, revoked.body.error]).toEqual([401, "login_required"]);
		const ended = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
		expect(ended.status).toBe(400);
	});

	it("answers 503 and keeps the transaction spent when the lockout cannot settle a taken proof", async () => {
		const s = await serve();
		const { secret } = await s.enrollCode();
		const { tx, factor } = await s.heldLogin();
		const verify = (proof: string) =>
			s.call("POST", "/session/mfa/verify", { transaction_id: tx, factor_id: factor(), proof });
		// The first update spends the attempt; the lockout's place goes down just before the take.
		s.kept.beforeNextUpdate(async () => {
			s.kept.beforeNextUpdate(async () => {
				s.simulated.unreachable(true);
			});
		});
		const proved = await verify(`${secret}:1`);
		s.simulated.unreachable(false);
		expect([proved.status, s.jar().has("__Host-session")]).toEqual([503, false]);
		expect((await verify(`${secret}:2`)).status).toBe(400);
	});
});

describe("the operator's numbers", () => {
	/** A wrong guess at a held login of a subject with a code factor, then a right one after `ms` on the places' clocks. */
	const guessed = async (lockout: Record<string, number | string>, ms: number) => {
		const s = await serve({ lockout });
		const { secret } = await s.enrollCode();
		const { tx, factor } = await s.heldLogin();
		const verify = (proof: string) =>
			s.call("POST", "/session/mfa/verify", { transaction_id: tx, factor_id: factor(), proof });
		const wrong = await verify("x:1");
		s.lagStores(ms);
		return [wrong.status, (await verify(`${secret}:1`)).body.hold];
	};
	const quick = { backoff: "1s", "max-backoff": "1s" };
	it.each([
		["backoff", { threshold: 1, backoff: "2s" }, 1500],
		["budget", { ...quick, threshold: 1, budget: 1, "budget-window": "10s" }, 1500],
		["hard", { ...quick, threshold: 1, budget: 1, "hard-limit": 1 }, 0],
	])(
		"holds by the lockout's numbers, its times written with their unit: %s",
		async (hold, lockout, ms) => {
			expect(await guessed(lockout, ms)).toEqual([401, hold]);
		},
	);

	it("refuses to boot with lockout numbers rate-limit cannot use", async () => {
		await serve();
		const refused = await serve({ lockout: { threshold: 20, budget: 10 } }).catch((e) => e);
		const reasons = (refused as BootRefused).refusals.map((r) => `${r.where}: ${r.reason}`);
		expect([...new Set(reasons)]).toEqual([
			"mfa-flows: lockout policy: threshold, budget and hard limit must not decrease",
		]);
	});

	it("refuses to boot with a time under its name in seconds, or naming no unit", async () => {
		const before = [{ "window-seconds": 300 }, { lockout: { "backoff-seconds": 900 } }];
		for (const settings of [...before, { window: 300 as unknown as string }]) {
			await expect(serve(settings as object), JSON.stringify(settings)).rejects.toBeInstanceOf(
				BootRefused,
			);
		}
	});

	it("counts the forms per source in a window of seconds", async () => {
		const s = await serve({ requests: 1, window: "1s" });
		await s.signIn();
		const stepUp = () => s.call("POST", "/session/mfa/step-up", {});
		expect([(await stepUp()).status, (await stepUp()).status]).toEqual([403, 429]);
		s.lagStores(1100);
		expect((await stepUp()).status).toBe(403);
	});
});

describe("audit events", () => {
	const from = "198.51.100.1";
	const event = (kind: string, attributes: Record<string, string>) => ({
		kind,
		subject: "alice",
		attributes,
		at: expect.any(Number),
	});
	it("records a refused proof and a verified one with the source, never the proof, and no challenge none was sent for", async () => {
		const s = await serve();
		const { secret } = await s.enrollCode();
		s.events.length = 0;
		const { tx, factor: id } = await s.heldLogin();
		const verify = (proof: string, transaction = tx) =>
			s.call("POST", "/session/mfa/verify", {
				transaction_id: transaction,
				factor_id: id("code"),
				proof,
			});
		expect((await verify("x:1")).status).toBe(401);
		expect((await verify(`${secret}:1`, "unknown")).status).toBe(400);
		expect((await verify(`${secret}:1`)).status).toBe(200);
		const started = await s.call("POST", "/session/mfa/step-up");
		const raise = String(started.body.transaction);
		expect((await verify(`${secret}:1`, raise)).status).toBe(401);
		expect((await verify(`${secret}:2`, raise)).status).toBe(200);
		const factor = id("code");
		expect(s.events).toEqual([
			event("mfa.verify.failure", { purpose: "login", factor, reason: "invalid", source: from }),
			event("mfa.verified", { purpose: "login", factor, source: from }),
			event("mfa.verify.failure", { purpose: "step-up", factor, reason: "replayed", source: from }),
			event("mfa.verified", { purpose: "step-up", factor, source: from }),
		]);
		expect(JSON.stringify(s.events)).not.toContain(secret);
	});

	it("records each refusal of a held subject, and a way back as a recovery code used and verified", async () => {
		const s = await serve({
			lockout: { threshold: 1, backoff: "15m", budget: 10, "hard-limit": 100 },
		});
		const { done } = await s.enrollCode();
		const first = await s.heldLogin();
		await s.call("POST", "/session/mfa/verify", {
			transaction_id: first.tx,
			factor_id: first.factor(),
			proof: "x:1",
		});
		const { tx, factor: id } = await s.heldLogin();
		s.events.length = 0;
		const locked = await s.call("POST", "/session/mfa/verify", {
			transaction_id: tx,
			factor_id: id("code"),
			proof: "x:2",
		});
		expect(locked.status).toBe(429);
		const back = await s.call("POST", "/session/mfa/verify", {
			transaction_id: tx,
			factor_id: id("backup"),
			proof: (done.body.recovery_codes as string[])[0] ?? "",
		});
		expect(back.status).toBe(200);
		expect(s.events).toEqual([
			event("mfa.locked", { purpose: "login", factor: id("code"), hold: "backoff", source: from }),
			event("mfa.recovery_code.used", { kind: "backup", factor: id("backup") }),
			event("mfa.verified", { purpose: "login", factor: id("backup"), source: from }),
		]);
	});

	it("records a challenge sent with its factor's kind, and none for a kind that sends none", async () => {
		const s = await serve({}, [sending]);
		await s.signIn();
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "sending" });
		await s.call("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: "first",
		});
		const { tx, factor } = await s.heldLogin();
		s.events.length = 0;
		const challenge = (kind: string) =>
			s.call("POST", "/session/mfa/challenge", { transaction_id: tx, factor_id: factor(kind) });
		expect((await challenge("sending")).status).toBe(200);
		expect((await challenge("backup")).status).toBe(200);
		expect(s.events).toEqual([
			event("mfa.challenge.sent", { kind: "sending", purpose: "login", source: from }),
		]);
	});

	it("records the start of a hold with the wrong guess that starts it, never with a proof right once", async () => {
		const s = await serve({
			lockout: { threshold: 2, backoff: "15m", budget: 10, "hard-limit": 100 },
		});
		const { secret } = await s.enrollCode();
		const first = await s.heldLogin();
		const proved = await s.call("POST", "/session/mfa/verify", {
			transaction_id: first.tx,
			factor_id: first.factor(),
			proof: `${secret}:1`,
		});
		expect(proved.status).toBe(200);
		const { tx, factor: id } = await s.heldLogin();
		s.events.length = 0;
		const verify = (proof: string) =>
			s.call("POST", "/session/mfa/verify", { transaction_id: tx, factor_id: id(), proof });
		const answers = [];
		for (const proof of ["x:1", `${secret}:1`, "x:2", `${secret}:2`]) {
			answers.push((await verify(proof)).status);
		}
		expect(answers).toEqual([401, 401, 401, 429]);
		const judged = { purpose: "login", factor: id(), source: from };
		expect(s.events).toEqual([
			event("mfa.verify.failure", { ...judged, reason: "invalid" }),
			event("mfa.verify.failure", { ...judged, reason: "replayed" }),
			event("mfa.verify.failure", { ...judged, reason: "invalid" }),
			event("mfa.locked.first", { ...judged, hold: "backoff" }),
			event("mfa.locked", { ...judged, hold: "backoff" }),
		]);
	});
});

describe("transactions on the kernel's clock", () => {
	it("ends a transaction at its deadline on the kernel's clock, whatever the store's clock says", async () => {
		const s = await serve({ "transaction-lifetime": "1m" });
		await s.enrollCode();
		const { tx } = await s.heldLogin();
		s.lagStores(-600_000);
		clock.shift += 58_000;
		const before = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
		expect(before.status).toBe(200);
		expect([1, 2]).toContain(before.body.expires_in);
		clock.shift += 2000;
		const after = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
		expect(after.status).toBe(400);
	});

	it("judges a revocation against the transaction's start on the kernel's clock", async () => {
		const s = await serve();
		const { secret } = await s.enrollCode();
		await s.app.get(subjectRevocation).revoke("alice");
		clock.shift += 2000;
		s.lagStores(-600_000);
		const { tx, factor } = await s.heldLogin();
		const proved = await s.call("POST", "/session/mfa/verify", {
			transaction_id: tx,
			factor_id: factor(),
			proof: `${secret}:1`,
		});
		expect(proved.status).toBe(200);
	});

	it("ends a transaction with the attempt that uses up its limit", async () => {
		const s = await serve({ "attempts-per-transaction": 2 });
		await s.enrollCode();
		const { tx, factor } = await s.heldLogin();
		for (const left of [1, 0]) {
			const wrong = await s.call("POST", "/session/mfa/verify", {
				transaction_id: tx,
				factor_id: factor(),
				proof: "x:1",
			});
			expect(wrong.body.attempts_remaining).toBe(left);
		}
		const ended = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
		expect(ended.status).toBe(400);
		await s.signIn("bea");
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" });
		const enrollment = String(begun.body.transaction);
		for (const left of [1, 0]) {
			const wrong = await s.call("POST", "/session/mfa/enrollment/complete", {
				transaction_id: enrollment,
				proof: "x:0",
			});
			expect(wrong.body.attempts_remaining).toBe(left);
		}
		const spent = await s.call("GET", "/session/mfa/transaction", { transaction_id: enrollment });
		expect(spent.status).toBe(400);
	});

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

	it("keeps a taken transaction until its lifetime, read as unknown", async () => {
		const s = await serve({ "transaction-lifetime": "1m" });
		const { secret } = await s.enrollCode();
		const { tx, factor } = await s.heldLogin();
		const own = new Map(s.jar());
		const proved = await s.call("POST", "/session/mfa/verify", {
			transaction_id: tx,
			factor_id: factor(),
			proof: `${secret}:1`,
		});
		expect(proved.status).toBe(200);
		const again = await s.call(
			"GET",
			"/session/mfa/transaction",
			{ transaction_id: tx },
			{ jar: own },
		);
		expect(again.status).toBe(400);
		expect(s.kept.peek(tx)).toBeDefined();
		clock.shift += 60_000;
		expect(s.kept.peek(tx)).toBeUndefined();
	});
});

describe("mfa in a session", () => {
	it("raises a session by a step-up under a new cookie, and the old cookie is no use after", async () => {
		const s = await serve();
		const { secret } = await s.enrollCode();
		const old = s.jar().get("__Host-session");
		const started = await s.call("POST", "/session/mfa/step-up");
		const tx = String(started.body.transaction);
		const factors = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
		const raised = await s.call("POST", "/session/mfa/verify", {
			transaction_id: tx,
			factor_id: idOf(factors, "code"),
			proof: `${secret}:3`,
		});
		expect([raised.status, raised.body]).toEqual([200, { step_up: "verified" }]);
		const fresh = s.jar().get("__Host-session");
		expect(fresh).not.toBe(old);
		const entered = await s.app
			.get(sessions)
			.enter(testRequest({ headers: new Map([["cookie", `__Host-session=${fresh}`]]) }));
		expect(entered?.context.amr).toEqual(["pwd", "otp", "mfa"]);
		expect(
			await s.app
				.get(sessions)
				.enter(testRequest({ headers: new Map([["cookie", `__Host-session=${old}`]]) })),
		).toBeUndefined();
	});

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
const slowGuess = defineModule({ name: "kind-slow-guess" }, (m) => [
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
	const enroll = async (
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
	it("never raises a session other than the one that started the step-up", async () => {
		const s = await serve();
		const { secret } = await s.enrollCode("eve");
		const eve = new Map(s.jar());
		await s.signIn("vic");
		const victim = s.jar().get("__Host-session") ?? "";
		const started = await s.call("POST", "/session/mfa/step-up", {}, { jar: eve });
		const tx = String(started.body.transaction);
		const info = await s.call(
			"GET",
			"/session/mfa/transaction",
			{ transaction_id: tx },
			{ jar: eve },
		);
		const factor = idOf(info, "code");
		const swapped = new Map(eve);
		swapped.set("__Host-session", victim);
		const raised = await s.call(
			"POST",
			"/session/mfa/verify",
			{ transaction_id: tx, factor_id: factor, proof: `${secret}:1` },
			{ jar: swapped },
		);
		expect(raised.status).toBe(400);
		const entered = await s.app
			.get(sessions)
			.enter(testRequest({ headers: new Map([["cookie", `__Host-session=${victim}`]]) }));
		expect(entered?.context.amr).toEqual(["pwd"]);
	});

	it("lets a single-use proof through once however many requests race with it", async () => {
		const s = await serve({}, [slowOnce]);
		await enroll(s, "una", "once", "o1");
		const held = [await s.heldLogin("una"), await s.heldLogin("una")];
		const answers = await Promise.all(
			held.map(({ tx, jar, factor }) =>
				s.call(
					"POST",
					"/session/mfa/verify",
					{ transaction_id: tx, factor_id: factor("once"), proof: "o2" },
					{ jar },
				),
			),
		);
		expect(answers.filter((r) => r.status === 200)).toHaveLength(1);
	});

	it("judges no more racing guesses than the lockout and the transaction allow", async () => {
		const s = await serve(
			{
				"attempts-per-transaction": 2,
				lockout: { threshold: 3, budget: 10, "hard-limit": 100 },
			},
			[slowGuess],
		);
		await enroll(s, "gus", "guess", "g");
		const guess = ({ tx, jar, factor }: Awaited<ReturnType<typeof s.heldLogin>>) =>
			s.call(
				"POST",
				"/session/mfa/verify",
				{ transaction_id: tx, factor_id: factor("guess"), proof: "x" },
				{ jar },
			);
		const one = await s.heldLogin("gus");
		// Enrolling judged a proof too.
		verifies.guess = 0;
		await Promise.all(Array.from({ length: 4 }, () => guess(one)));
		expect(verifies.guess).toBeLessThanOrEqual(2);
		// One at a time: each browser keeps its own transaction cookie.
		const others: Awaited<ReturnType<typeof s.heldLogin>>[] = [];
		for (let i = 0; i < 4; i++) others.push(await s.heldLogin("gus"));
		verifies.guess = 0;
		await Promise.all(others.map(guess));
		expect(verifies.guess).toBeLessThanOrEqual(1);
	});

	it("spends an attempt only from the transaction as last read, when another request spends it in between", async () => {
		const s = await serve(
			{
				"attempts-per-transaction": 2,
				lockout: { threshold: 50, budget: 50, "hard-limit": 100 },
			},
			[slowGuess],
		);
		await enroll(s, "ivy", "guess", "g");
		const one = await s.heldLogin("ivy");
		const guess = () =>
			s.call(
				"POST",
				"/session/mfa/verify",
				{ transaction_id: one.tx, factor_id: one.factor("guess"), proof: "x" },
				{ jar: one.jar },
			);
		// Enrolling judged a proof too.
		verifies.guess = 0;
		s.kept.beforeNextUpdate(async () => {
			await guess();
			await guess();
		});
		const late = await guess();
		expect(verifies.guess).toBe(2);
		expect(late.status).toBe(400);
	});

	it("counts nothing against the subject for a right proof sent twice", async () => {
		const s = await serve({ lockout: { threshold: 2, budget: 2, "hard-limit": 100 } }, [slowGuess]);
		await enroll(s, "dan", "guess", "g");
		for (let round = 0; round < 3; round++) {
			const one = await s.heldLogin("dan");
			const send = () =>
				s.call(
					"POST",
					"/session/mfa/verify",
					{ transaction_id: one.tx, factor_id: one.factor("guess"), proof: "g" },
					{ jar: new Map(one.jar) },
				);
			const answers = await Promise.all([send(), send()]);
			expect(answers.map((a) => a.status).sort()).toEqual([200, 400]);
		}
	});

	it("refuses a recovery code whose set was replaced while it was being judged", async () => {
		const s = await serve();
		const { done } = await s.enrollCode("rex");
		const codes = done.body.recovery_codes as string[];
		const one = await s.heldLogin("rex");
		during.backup = async () => {
			const reissued = await s.app.get(factors).reissue("rex");
			expect(reissued.kind).toBe("reissued");
		};
		const used = await s.call(
			"POST",
			"/session/mfa/verify",
			{ transaction_id: one.tx, factor_id: one.factor("backup"), proof: codes[0] ?? "" },
			{ jar: one.jar },
		);
		expect(used.status).toBe(401);
	});

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

	it("never takes a transaction or a proof from the URL", async () => {
		const s = await serve();
		const { secret } = await s.enrollCode("quinn");
		const { tx, jar, factor } = await s.heldLogin("quinn");
		const res = await s.call(
			"POST",
			`/session/mfa/verify?transaction_id=${tx}`,
			{ factor_id: factor(), proof: `${secret}:1` },
			{ jar },
		);
		expect(res.status).toBe(400);
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
				const held = transactionsOver({
					store: await c.get(transactionStore),
					listings: await c.get(transactionListings),
					jar: await c.get(cookies),
					log: c.log,
					random: c.random.bytes,
					clock: c.clock,
					ttlMs: 300_000,
					attempts: 5,
				});
				return (tx, subject, secret) =>
					held.hold(
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

	it("takes only a raise that added a second factor as a recent second factor", async () => {
		const s = await serve();
		await s.enrollCode("rho");
		clock.shift += 400_000;
		const cookie = s.jar().get("__Host-session") ?? "";
		const raised = await s.app
			.get(sessions)
			.raise(testRequest({ headers: new Map([["cookie", `__Host-session=${cookie}`]]) }), ["hwk"]);
		const fresh = (raised?.cookies[0] ?? "").split(";")[0]?.split("=")[1] ?? "";
		// Changing a factor enters the session at the credential-changing level.
		const entry = await s.app
			.get(sessions)
			.enterFor(
				testRequest({ headers: new Map([["cookie", `__Host-session=${fresh}`]]) }),
				"credentials",
			);
		expect(entry.kind === "short" ? entry.answer : entry.kind).toEqual({
			error: "step_up_required",
		});
	});
});

describe("mfa bodies", () => {
	const json = { json: true };

	it("takes every POST's values from a JSON body as from a form, a member that is not a string being absent", async () => {
		const s = await serve();
		await s.signIn("judy");
		const begun = await s.call("POST", "/session/mfa/enrollment", { kind: "code" }, json);
		const tx = String(begun.body.transaction);
		const odd = await s.call(
			"POST",
			"/session/mfa/enrollment/complete",
			{ transaction_id: tx, proof: 0, label: "x" },
			json,
		);
		expect([odd.status, odd.body]).toEqual([401, { error: "mfa_invalid", attempts_remaining: 4 }]);
		const done = await s.call(
			"POST",
			"/session/mfa/enrollment/complete",
			{ transaction_id: tx, proof: `${begun.body.secret}:0`, label: "phone" },
			json,
		);
		expect([done.status, (done.body.factor as { label?: string }).label]).toEqual([200, "phone"]);
		expect(done.body.recovery_codes).toHaveLength(2);
		const { tx: login, factor } = await s.heldLogin("judy");
		const id = factor();
		const verify = (body: Record<string, unknown>) =>
			s.call("POST", "/session/mfa/verify", body, json);
		expect((await verify({ transaction_id: [login], factor_id: id, proof: "x:1" })).status).toBe(
			400,
		);
		const noFactor = await verify({ transaction_id: login, factor_id: 1, proof: "x:1" });
		expect([noFactor.status, noFactor.body.error_description]).toEqual([400, "unknown factor"]);
		const wrong = await verify({ transaction_id: login, factor_id: id, proof: "x:1" });
		expect([wrong.status, wrong.body]).toEqual([
			401,
			{ error: "mfa_invalid", attempts_remaining: 4 },
		]);
		const right = await verify({
			transaction_id: login,
			factor_id: id,
			proof: `${begun.body.secret}:1`,
		});
		expect([right.status, right.body]).toEqual([200, { redirect_to: "https://app.example/back" }]);
		const up = await s.call("POST", "/session/mfa/step-up", {}, json);
		expect([up.status, typeof up.body.transaction]).toEqual([200, "string"]);
	});

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

	it("answers 415 to a POST whose body is neither a form nor JSON, or that has none", async () => {
		const s = await serve();
		await s.signIn("kim");
		const port = s.app.get(listening).port();
		for (const path of [
			"/session/mfa/challenge",
			"/session/mfa/verify",
			"/session/mfa/step-up",
			"/session/mfa/enrollment",
			"/session/mfa/enrollment/complete",
		]) {
			for (const body of [{ type: "text/plain", text: "kind=code" }, undefined]) {
				const res = await fetch(`http://127.0.0.1:${port}${path}`, {
					method: "POST",
					headers: {
						"x-forwarded-proto": "https",
						"x-forwarded-for": "198.51.100.1",
						origin: "https://as.example",
						cookie: [...s.jar()].map(([k, v]) => `${k}=${v}`).join("; "),
						...(body ? { "content-type": body.type } : {}),
					},
					...(body ? { body: body.text } : {}),
				});
				expect([path, res.status]).toEqual([path, 415]);
			}
		}
	});

	it("takes the transaction from the body or the MFA-Transaction header, and refuses the two when they differ", async () => {
		const s = await serve();
		const { secret } = await s.enrollCode("lee");
		const { tx, factor } = await s.heldLogin("lee");
		const id = factor();
		const header = (value: string) => ({ headers: { "mfa-transaction": value } });
		const differ = await s.call(
			"POST",
			"/session/mfa/verify",
			{ transaction_id: tx, factor_id: id, proof: "x:1" },
			header(`${tx}x`),
		);
		expect([differ.status, differ.body.error]).toEqual([400, "invalid_request"]);
		const twice = new URLSearchParams([
			["transaction_id", tx],
			["transaction_id", tx],
			["factor_id", id],
			["proof", "x:1"],
		]);
		const repeated = await s.call("POST", "/session/mfa/verify", {}, { form: twice });
		expect([repeated.status, repeated.body.error]).toEqual([400, "invalid_request"]);
		const info = await s.call("GET", "/session/mfa/transaction", { transaction_id: tx });
		expect(info.body.attempts_remaining).toBe(5);
		const byHeader = await s.call(
			"POST",
			"/session/mfa/verify",
			{ transaction_id: "", factor_id: id, proof: "x:1" },
			{ ...json, ...header(tx) },
		);
		expect([byHeader.status, byHeader.body.attempts_remaining]).toEqual([401, 4]);
		const both = await s.call(
			"POST",
			"/session/mfa/verify",
			{ transaction_id: tx, factor_id: id, proof: `${secret}:1` },
			header(tx),
		);
		expect(both.status).toBe(200);
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
