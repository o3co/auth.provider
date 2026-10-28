import { testRequest } from "@mod/http/testing";
import { defineModule, Unavailable } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { type Witnessing, witnessing } from "@mod/mfa-extensions";
import { sessions } from "@mod/session";
import { revocations } from "@mod/subject-revocation";
import { beforeEach, describe, expect, it } from "vitest";
import { mfaReset } from "../src/contract.ts";
import { clock, logged, runtime, serve } from "./harness.ts";

describe("a reset composed with mfa-flows and its stores", () => {
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
		expect(await s.app.get(mfaReset).run("ann", { requestedBy: "ticket-7" })).toMatchObject({
			kind: "done",
			removed: 2,
		});
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
		expect(await s.app.get(mfaReset).run("cal")).toMatchObject({ kind: "done", removed: 2 });
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
	it("answers stopped at the factors, with no removed, where the witness fails after the factors went", async () => {
		// A witness whose mark cannot be cleared: mfa removes the factors first, then fails on the mark.
		const failing: Witnessing = {
			standing: async (_subject, counts) => (counts ? "held" : "none"),
			settle: async () => {},
			cleared: async () => {
				throw new Unavailable("witness");
			},
		};
		const witness = defineModule(
			{ name: "failing-witness", replicaSafe: false, takes: [] },
			(m) => [m.contribute(witnessing).by(() => failing)],
		);
		const s = await serve({}, [witness]);
		await s.enrollCode("dot");
		expect(await s.app.get(mfaReset).run("dot")).toEqual({ kind: "stopped", at: "factors" });
		// The factors went all the same: whether they did is what removed would have told.
		clock.shift += 1000;
		expect((await s.login("dot")).kind).toBe("opened");
	});
});

it("takes all it names, composed with mfa-flows and its stores", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused((await serve()).input))["mfa-reset"]).toBeUndefined();
});
