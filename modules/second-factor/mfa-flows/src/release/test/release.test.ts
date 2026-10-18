import type { AuditEvent } from "@mod/audit";
import { testRequest } from "@mod/http/testing";
import { isUnavailable, Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import { longestRecentMs } from "@mod/mfa";
import type { LockoutPolicy, Released, ReleaseTerms, Standing } from "@mod/rate-limit";
import type { Answer, AuthContext, Entry } from "@mod/session";
import { subjectRevocation } from "@mod/subject-revocation";
import { describe, expect, it } from "vitest";
import { clock, serve } from "../../../test/harness.ts";
import type { PermitResult, PermitState } from "../../permits/permits.ts";
import { releaseOver } from "../release.ts";

const policy = {} as LockoutPolicy;
const margin = 300_000;
const at = 1_800_000_000_000;
const context: AuthContext = { subject: "ann", amr: ["pwd", "mfa"], authenticatedAt: at };
const entered = (): Entry => ({
	kind: "entered",
	session: { id: "handle-1", context },
	endsAt: at + 3_600_000,
});
const ready: PermitState = { kind: "ready", id: "permit-1", proofAt: at };

/** As subject-revocation compares: in seconds, a time in the boundary's own second revoked too. */
const comparedTo = (boundary: number | undefined, time: number) =>
	boundary !== undefined && Math.floor(time / 1000) <= Math.floor(boundary / 1000)
		? "revoked"
		: "valid";

/** The release over parts that answer as told, keeping the calls in order. */
function over(
	told: {
		entry?: Entry;
		permit?: PermitState;
		standing?: Standing;
		boundary?: number;
		boundAfter?: boolean;
		released?: Released | (() => Released);
		failing?: "standing" | "check" | "bound" | "release" | "use";
	} = {},
) {
	const calls: unknown[][] = [];
	const events: AuditEvent[] = [];
	const logged = recordingLog();
	const fail = (part: string) => {
		if (told.failing === part) throw new Unavailable(part);
	};
	const handlers = releaseOver({
		sessions: {
			enterFor: async (_request, level) => {
				calls.push(["enter", level]);
				return told.entry ?? entered();
			},
		},
		permits: {
			of: async (handle) => {
				calls.push(["permit", handle]);
				return told.permit ?? ready;
			},
			use: async (handle, permit, result) => {
				calls.push(["use", handle, permit.proofAt, result]);
				fail("use");
			},
		},
		lockouts: {
			standing: async (name, key) => {
				calls.push(["standing", name, key]);
				fail("standing");
				return told.standing ?? {};
			},
			releaseUnder: async (name, key, _policy, terms: ReleaseTerms) => {
				calls.push(["release", name, key, terms]);
				fail("release");
				const answer = told.released ?? { kind: "unchanged" };
				return typeof answer === "function" ? answer() : answer;
			},
		},
		revocation: {
			check: async (subject, time) => {
				calls.push(["check", subject, time]);
				fail("check");
				return comparedTo(told.boundary, time);
			},
		},
		factors: {
			guessableBoundAfter: async (subject, after) => {
				calls.push(["bound", subject, after]);
				fail("bound");
				return told.boundAfter ?? false;
			},
		},
		policy,
		now: () => at,
		audit: { record: (event) => events.push({ ...event, at: 0 }) },
		log: logged.log,
	});
	const run = async () => {
		const res = await handlers.release(testRequest());
		return [res.status, (res.body as { json: unknown }).json];
	};
	return { run, calls, events, lines: () => logged.lines() };
}

const termsOf = (calls: unknown[][]) => calls.find((c) => c[0] === "release")?.[3] as ReleaseTerms;
const named = (calls: unknown[][]) => calls.map((c) => c[0]);
const released = (cleared: Partial<Record<"budget" | "run" | "hard", boolean>>, extra = {}) =>
	({
		kind: "released",
		generation: 3,
		cleared: { budget: false, run: false, hard: false, ...cleared },
		...extra,
	}) as Released;
const refused = {
	error: "mfa_lock_release_refused",
	error_description: "Change the account's password, sign in again, then release",
	reason: "not_revoked_since",
};
const exemptRequired = {
	error: "mfa_exempt_proof_required",
	error_description: "Verify a recovery code or a passkey first, then release",
};
const heldText =
	"Guessable second factors stay held until each is replaced: replace them, verify a recovery code or a passkey again, then release";

describe("a user's own release of the second-factor lockout", () => {
	it("enters the session to change credentials, then asks for its permit, answering 401, the requirement's 403, or the exempt-proof refusal", async () => {
		expect(await over({ entry: { kind: "absent" } }).run()).toEqual([
			401,
			{ error: "login_required" },
		]);
		const stepUp = { error: "step_up_required" };
		const short = (answer: Answer): Entry => ({ kind: "short", requirement: "mfa", answer });
		expect(await over({ entry: short(stepUp) }).run()).toEqual([403, stepUp]);
		const none = over({ permit: { kind: "none" } });
		expect(await none.run()).toEqual([403, exemptRequired]);
		expect(named(none.calls)).toEqual(["enter", "check", "permit"]);
		expect(none.calls[0]).toEqual(["enter", "credentials"]);
	});

	it("answers unavailable, releasing nothing, while the boundary stands more than five minutes ahead of the clock", async () => {
		const ahead = over({ boundary: at + margin + 1000 });
		expect(await ahead.run()).toEqual([503, { error: "temporarily_unavailable" }]);
		expect(ahead.calls).toEqual([
			["enter", "credentials"],
			["check", "ann", at + margin],
		]);
		expect(ahead.events).toEqual([]);
		expect(ahead.lines()).toEqual([
			{ level: "error", event: "mfa-flows.lock_release_boundary_ahead", fields: {} },
		]);
		expect((await over({ boundary: at + margin - 1000 }).run())[0]).toBe(409);
	});

	it("forgives the count only once the account was revoked more than five minutes after the first counted failure, in whole seconds", async () => {
		const first = at - 3_600_000;
		const just = over({ standing: { firstFailureAt: first }, boundary: first + margin + 999 });
		await just.run();
		expect(named(just.calls)).toEqual(["enter", "check", "permit", "standing", "check", "release"]);
		expect(just.calls[4]).toEqual(["check", "ann", first + margin + 1000]);
		expect(termsOf(just.calls)).not.toHaveProperty("forgive");
		const past = over({ standing: { firstFailureAt: first }, boundary: first + margin + 1000 });
		await past.run();
		expect(termsOf(past.calls)).toMatchObject({ forgive: { firstFailureAt: first } });
		const none = over({ standing: {} });
		await none.run();
		expect(named(none.calls)).toEqual(["enter", "check", "permit", "standing", "release"]);
		expect(termsOf(none.calls)).toMatchObject({ forgive: {} });
	});

	it("lifts a fixed hold only once every guessable factor was bound more than five minutes after it", async () => {
		const fixedAt = at - 60_000;
		const kept = over({ standing: { fixedAt }, boundAfter: false });
		await kept.run();
		expect(kept.calls).toContainEqual(["bound", "ann", fixedAt + margin]);
		expect(termsOf(kept.calls)).not.toHaveProperty("lift");
		const lifted = over({ standing: { fixedAt }, boundAfter: true });
		await lifted.run();
		expect(termsOf(lifted.calls)).toMatchObject({ lift: { fixedAt } });
	});

	it("names the release by the session's permit, kept for the longest recent window", async () => {
		const o = over();
		await o.run();
		expect(termsOf(o.calls)).toMatchObject({ once: { id: "permit-1", keepMs: longestRecentMs } });
	});

	it("answers released, or a hold left standing with when to bind again, and spends the permit on it", async () => {
		const fixedAt = at - 60_000;
		const rebind = new Date(fixedAt + margin).toISOString();
		const plain = over({ released: released({ budget: true, run: true }) });
		expect(await plain.run()).toEqual([200, { lock: "released" }]);
		expect(plain.calls.at(-1)).toEqual(["use", "handle-1", at, { lock: "released" }]);
		const held = { lock: "held", hold: "hard", description: heldText, rebind_after: rebind };
		const standing = over({ released: released({ budget: true }, { fixedAt }) });
		expect(await standing.run()).toEqual([200, held]);
		expect(standing.calls.at(-1)).toEqual(["use", "handle-1", at, { lock: "held", fixedAt }]);
	});

	it("refuses without spending the permit, so the same proof may release once the account is set right", async () => {
		const fixedAt = at - 60_000;
		const plain = over({ released: { kind: "unchanged" } });
		expect(await plain.run()).toEqual([409, refused]);
		expect(named(plain.calls)).not.toContain("use");
		const held = over({ released: { kind: "unchanged", fixedAt } });
		expect(await held.run()).toEqual([
			409,
			{ ...refused, rebind_after: new Date(fixedAt + margin).toISOString() },
		]);
	});

	it("answers a used permit with what it answered, asking nothing more", async () => {
		const result: PermitResult = { lock: "held", fixedAt: at };
		const used = over({ permit: { kind: "used", result } });
		const [status, body] = await used.run();
		expect([status, (body as { lock: string }).lock]).toEqual([200, "held"]);
		expect(named(used.calls)).toEqual(["enter", "check", "permit"]);
		expect(used.events).toEqual([]);
	});

	it("answers releases racing on one permit alike, one applied and the other already", async () => {
		const fixedAt = at - 60_000;
		let applied = false;
		const once = () => {
			const answer = applied
				? ({ kind: "already", generation: 3, fixedAt } as const)
				: released({ budget: true }, { fixedAt });
			applied = true;
			return answer;
		};
		const racing = over({ released: once });
		const [first, second] = await Promise.all([racing.run(), racing.run()]);
		expect(second).toEqual(first);
		expect(racing.events).toHaveLength(1);
		expect(racing.lines().map((l) => l.fields)).toEqual([
			{ outcome: "held" },
			{ outcome: "repeated" },
		]);
	});

	it("answers the same once more after its permit could not be marked used, rate-limit telling it was already applied", async () => {
		const failed = over({ released: released({ budget: true, run: true }), failing: "use" });
		await expect(failed.run()).rejects.toSatisfy(isUnavailable);
		expect(failed.events).toHaveLength(1);
		const again = over({ released: { kind: "already", generation: 3 } });
		expect(await again.run()).toEqual([200, { lock: "released" }]);
		expect(again.events).toEqual([]);
	});

	it("records only a release applied now, with what it cleared, and logs each outcome", async () => {
		const applied = over({ released: released({ run: true, hard: true }) });
		await applied.run();
		expect(applied.events).toEqual([
			{
				kind: "mfa.lock.recovered",
				subject: "ann",
				attributes: {
					operation: "recover",
					generation: "3",
					week: "false",
					run: "true",
					hard: "true",
					source: "127.0.0.1",
				},
				at: 0,
			},
		]);
		expect(applied.lines()).toEqual([
			{ level: "info", event: "mfa-flows.lock_release", fields: { outcome: "released" } },
		]);
		for (const [told, outcome] of [
			[{ kind: "already", generation: 3 }, "repeated"],
			[{ kind: "unchanged" }, "refused"],
			[{ kind: "unchanged", fixedAt: at }, "refused"],
		] as const) {
			const quiet = over({ released: told });
			await quiet.run();
			expect(quiet.events).toEqual([]);
			expect(quiet.lines().map((l) => l.fields)).toEqual([{ outcome }]);
		}
		const held = over({ released: released({ budget: true }, { fixedAt: at }) });
		await held.run();
		expect(held.lines().map((l) => l.fields)).toEqual([{ outcome: "held" }]);
		expect(JSON.stringify(held.lines())).not.toContain("rebind");
	});

	it("fails unavailable when a part cannot answer, releasing nothing", async () => {
		for (const failing of ["standing", "check", "bound", "release"] as const) {
			const o = over({ standing: { firstFailureAt: at, fixedAt: at }, failing });
			await expect(o.run(), failing).rejects.toSatisfy(isUnavailable);
			expect(o.events).toEqual([]);
		}
	});
	it("is served, refusing a session that only a guessable factor let in", async () => {
		const s = await serve();
		const path = "/session/mfa/lock/release";
		expect(await s.call("POST", path)).toEqual({ status: 401, body: { error: "login_required" } });
		const { secret } = await s.enrollCode("ann");
		const { tx, factor, jar } = await s.heldLogin("ann");
		const proof = { transaction_id: tx, factor_id: factor(), proof: `${secret}:1` };
		expect((await s.call("POST", "/session/mfa/verify", proof, { jar })).status).toBe(200);
		expect(await s.call("POST", path, {}, { jar })).toEqual({
			status: 403,
			body: {
				error: "mfa_exempt_proof_required",
				error_description: "Verify a recovery code or a passkey first, then release",
			},
		});
	});

	it("releases the real lockout for a session a recovery code let in, once, answering the same again", async () => {
		const s = await serve({
			lockout: { threshold: 2, backoff: "15m", budget: 10, "hard-limit": 100 },
		});
		const { done } = await s.enrollCode("bea");
		const codes = (done.body.recovery_codes ?? []) as string[];
		for (let i = 0; i < 2; i++) {
			const { tx, factor, jar } = await s.heldLogin("bea");
			await s.call(
				"POST",
				"/session/mfa/verify",
				{ transaction_id: tx, factor_id: factor(), proof: "x:9" },
				{ jar },
			);
		}
		// The account is revoked well after the failures, so they are forgiven.
		clock.shift += 6 * 60_000;
		await s.app.get(subjectRevocation).revoke("bea");
		clock.shift += 1000;
		const { tx, factor, jar } = await s.heldLogin("bea");
		const proof = { transaction_id: tx, factor_id: factor("backup"), proof: codes[0] ?? "" };
		expect((await s.call("POST", "/session/mfa/verify", proof, { jar })).status).toBe(200);
		const path = "/session/mfa/lock/release";
		const first = await s.call("POST", path, {}, { jar });
		expect(first).toEqual({ status: 200, body: { lock: "released" } });
		expect(await s.call("POST", path, {}, { jar })).toEqual(first);
		expect(s.events.filter((e) => e.kind === "mfa.lock.recovered")).toHaveLength(1);
	});
});
