import { testRequest } from "@mod/http/testing";
import { isUnavailable, Unavailable } from "@mod/kernel";
import { factors } from "@mod/mfa";
import { sessions } from "@mod/session";
import { revocations } from "@mod/subject-revocation";
import { beforeEach, describe, expect, it } from "vitest";
import {
	clock,
	during,
	factorsDown,
	logged,
	revocationsDown,
	runtime,
	serve,
} from "../../../test/harness.ts";
import { mfaReset } from "../../contract.ts";

describe("a reset by an operator", () => {
	const cleared = { by: "operator", kinds: "backup code", count: "2" };
	/** The reset's log lines since the test began. */
	let from = 0;
	const resetLines = () =>
		logged
			.lines()
			.slice(from)
			.filter((l) => l.event.startsWith("mfa-flows.reset"));
	beforeEach(() => {
		from = logged.lines().length;
	});
	it("ends the subject's sessions and pending logins, removes every factor and releases the lockout", async () => {
		const s = await serve({
			lockout: { threshold: 2, backoff: "15m", budget: 10, "hard-limit": 100 },
		});
		await s.enrollCode("ann");
		const signedIn = new Map(s.jar());
		for (let i = 0; i < 2; i++) {
			const { tx, factor } = await s.heldLogin("ann");
			await s.call("POST", "/session/mfa/verify", {
				transaction_id: tx,
				factor_id: factor(),
				proof: "x:1",
			});
		}
		const pending = await s.heldLogin("ann");
		await s.enrollCode("bob");
		s.events.length = 0;
		expect(await s.app.get(mfaReset).reset("ann", { requestedBy: "ticket-7" })).toBe(2);
		expect(s.events).toEqual([
			{
				kind: "mfa.reset",
				subject: "ann",
				attributes: {
					by: "operator",
					kinds: "backup code",
					count: "2",
					sessions: "true",
					sessionsAgain: "true",
					complete: "true",
					requestedBy: "ticket-7",
				},
				at: expect.any(Number),
			},
		]);
		expect(resetLines()).toEqual([{ level: "info", event: "mfa-flows.reset", fields: {} }]);
		const cookie = `__Host-session=${signedIn.get("__Host-session") ?? ""}`;
		const request = testRequest({ headers: new Map([["cookie", cookie]]) });
		expect(await s.app.get(sessions).enter(request)).toBeUndefined();
		const verify = { transaction_id: pending.tx, factor_id: pending.factor(), proof: "x:2" };
		expect((await s.call("POST", "/session/mfa/verify", verify, { jar: pending.jar })).status).toBe(
			401,
		);
		expect((await s.login("bob")).kind).toBe("held");
		clock.shift += 1000;
		expect((await s.login("ann")).kind).toBe("opened");
		const { secret } = await s.enrollCode("ann");
		const { tx, factor } = await s.heldLogin("ann");
		const right = { transaction_id: tx, factor_id: factor(), proof: `${secret}:1` };
		expect((await s.call("POST", "/session/mfa/verify", right)).status).toBe(200);
	});

	it("moves only the sessions boundary, leaving delegations to the grants that may outlive it", async () => {
		const s = await serve();
		await s.enrollCode("cal");
		const before = runtime.clock.now() - 1000;
		expect(await s.app.get(mfaReset).reset("cal")).toBe(2);
		const boundaries = s.app.get(revocations);
		expect(await boundaries.compare("cal", before, "sessions")).toBe("revoked");
		expect(await boundaries.compare("cal", before, "delegations")).toBe("valid");
		expect(s.events.at(-1)?.attributes).toEqual({
			by: "operator",
			kinds: "backup code",
			count: "2",
			sessions: "true",
			sessionsAgain: "true",
			complete: "true",
		});
	});

	it("opens no session for a login proved before the second boundary, whenever the session would open", async () => {
		const s = await serve();
		const { secret } = await s.enrollCode("kit");
		const { tx, factor } = await s.heldLogin("kit");
		clock.shift += 1000;
		// The proof passes; the reset runs whole before the take, and the login opens a second later.
		s.kept.beforeNextUpdate(async () => {
			s.kept.beforeNextUpdate(async () => {
				await s.app.get(mfaReset).reset("kit");
				clock.shift += 1000;
			});
		});
		const proof = { transaction_id: tx, factor_id: factor(), proof: `${secret}:1` };
		const proved = await s.call("POST", "/session/mfa/verify", proof);
		expect([proved.status, proved.body]).toEqual([401, { error: "login_required" }]);
		expect(s.jar().has("__Host-session")).toBe(false);
	});

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
		const reset = await enrolling("max", () => s.app.get(mfaReset).reset("max"));
		expect([reset.status, reset.body]).toEqual([401, { error: "login_required" }]);
		expect(await s.app.get(factors).held("max")).toEqual([]);
		const revoked = await enrolling("nia", () => s.app.get(revocations).record("nia"));
		expect([revoked.status, revoked.body]).toEqual([401, { error: "login_required" }]);
		expect(await s.app.get(factors).held("nia")).toEqual([]);
	});

	it("records an unfinished reset and rejects as unavailable, and a second run finishes it", async () => {
		const s = await serve();
		await s.enrollCode("dee");
		s.events.length = 0;
		revocationsDown.failNext("record");
		await expect(s.app.get(mfaReset).reset("dee")).rejects.toSatisfy(isUnavailable);
		expect(s.events.map((e) => e.attributes)).toEqual([
			{ by: "operator", sessions: "false", complete: "false" },
		]);
		expect(resetLines()).toEqual([
			{
				level: "warn",
				event: "mfa-flows.reset_incomplete",
				fields: { stoppedAt: "sessions", error: "Unavailable" },
			},
		]);
		expect((await s.login("dee")).kind).toBe("held");
		expect(await s.app.get(mfaReset).reset("dee")).toBe(2);
		expect(s.events.at(-1)?.attributes).toEqual({
			by: "operator",
			kinds: "backup code",
			count: "2",
			sessions: "true",
			sessionsAgain: "true",
			complete: "true",
		});
	});

	it("stops before the factors when the first revocation could not close every session", async () => {
		const s = await serve();
		await s.enrollCode("joy");
		s.events.length = 0;
		during.unfinishedRecords = 1;
		await expect(s.app.get(mfaReset).reset("joy")).rejects.toSatisfy(isUnavailable);
		expect(s.events.map((e) => e.attributes)).toEqual([
			{ by: "operator", sessions: "false", complete: "false" },
		]);
		expect(resetLines().map((line) => line.fields)).toEqual([
			{ stoppedAt: "sessions", error: "Unavailable" },
		]);
		clock.shift += 1000;
		expect((await s.login("joy")).kind).toBe("held");
	});

	it("answers a second revocation that could not close every session, after the factors went", async () => {
		const s = await serve();
		await s.enrollCode("kit");
		s.events.length = 0;
		during.release = async () => {
			during.unfinishedRecords = 1;
		};
		await expect(s.app.get(mfaReset).reset("kit")).rejects.toSatisfy(isUnavailable);
		expect(s.events.map((e) => e.attributes)).toEqual([
			{ ...cleared, sessions: "true", sessionsAgain: "false", complete: "false" },
		]);
	});

	it("moves the second boundary when releasing the lockout fails, and answers the first failure", async () => {
		const s = await serve();
		await s.enrollCode("fay");
		s.events.length = 0;
		// A login proved with a factor after the first boundary, a second later.
		let proved = 0;
		during.release = async () => {
			clock.shift += 1000;
			proved = runtime.clock.now();
			clock.shift += 1000;
			throw new Unavailable("rate-limit");
		};
		await expect(s.app.get(mfaReset).reset("fay")).rejects.toThrow(new Unavailable("rate-limit"));
		expect(await s.app.get(revocations).compare("fay", proved, "sessions")).toBe("revoked");
		expect(s.events.map((e) => e.attributes)).toEqual([
			{ ...cleared, sessions: "true", sessionsAgain: "true", complete: "false" },
		]);
		expect(resetLines().map((line) => line.fields)).toEqual([
			{ stoppedAt: "lock", error: "Unavailable" },
		]);
	});

	it("answers a failed second boundary after the factors went, and records the count", async () => {
		const s = await serve();
		await s.enrollCode("gus");
		s.events.length = 0;
		during.release = async () => revocationsDown.failNext("record");
		await expect(s.app.get(mfaReset).reset("gus")).rejects.toSatisfy(isUnavailable);
		expect(s.events.map((e) => e.attributes)).toEqual([
			{ ...cleared, sessions: "true", sessionsAgain: "false", complete: "false" },
		]);
		expect(resetLines().map((line) => line.fields)).toEqual([
			{ stoppedAt: "sessions", error: "Unavailable" },
		]);
		clock.shift += 1000;
		expect((await s.login("gus")).kind).toBe("opened");
	});

	it("answers and logs the first failure when the second boundary fails too", async () => {
		const s = await serve();
		await s.enrollCode("ivy");
		during.release = async () => {
			revocationsDown.failNext("record");
			throw new Unavailable("rate-limit");
		};
		await expect(s.app.get(mfaReset).reset("ivy")).rejects.toThrow(new Unavailable("rate-limit"));
		expect(resetLines().map((line) => line.fields)).toEqual([
			{ stoppedAt: "lock", error: "Unavailable" },
		]);
		expect(s.events.at(-1)?.attributes).toMatchObject({ sessionsAgain: "false" });
	});

	it("keeps the factors it could not remove and their lockout, ending the sessions twice all the same", async () => {
		const s = await serve({
			lockout: { threshold: 1, backoff: "15m", budget: 10, "hard-limit": 100 },
		});
		const { secret } = await s.enrollCode("hal");
		const first = await s.heldLogin("hal");
		const wrong = { transaction_id: first.tx, factor_id: first.factor(), proof: "x:1" };
		await s.call("POST", "/session/mfa/verify", wrong);
		s.events.length = 0;
		factorsDown.failNext("update");
		await expect(s.app.get(mfaReset).reset("hal")).rejects.toSatisfy(isUnavailable);
		expect(s.events.map((e) => e.attributes)).toEqual([
			{ by: "operator", sessions: "true", sessionsAgain: "true", complete: "false" },
		]);
		expect(resetLines().map((line) => line.fields)).toEqual([
			{ stoppedAt: "factors", error: "Unavailable" },
		]);
		clock.shift += 1000;
		const { tx, factor } = await s.heldLogin("hal");
		const right = { transaction_id: tx, factor_id: factor(), proof: `${secret}:1` };
		expect((await s.call("POST", "/session/mfa/verify", right)).status).toBe(429);
	});

	it("refuses a malformed subject or requester before anything is done", async () => {
		const s = await serve();
		await s.enrollCode("eli");
		s.events.length = 0;
		const reset = s.app.get(mfaReset);
		for (const [subject, requestedBy, what] of [
			["", undefined, "subject"],
			["eli", "", "requestedBy"],
			["eli", "r".repeat(257), "requestedBy"],
			["eli", "\ud800", "requestedBy"],
		] as const) {
			const options = requestedBy === undefined ? {} : { requestedBy };
			await expect(reset.reset(subject, options)).rejects.toThrow(new RangeError(what));
		}
		const odd = ["eli"] as unknown as string;
		await expect(reset.reset(odd)).rejects.toThrow(new RangeError("subject"));
		expect(s.events).toEqual([]);
		expect((await s.login("eli")).kind).toBe("held");
	});
});
