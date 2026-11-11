import { type Eraser, erasers } from "@mod/erasure-extensions";
import { type Assembly, contract, defineModule } from "@mod/kernel";
import { afterEach, expect, it } from "vitest";
import { clock, serve } from "./harness.ts";

afterEach(() => {
	clock.shift = 0;
});

const seen = contract<readonly Eraser[]>("mfa-flows-test.erasers");
/** Hands the test the erasers composed, as account erasure collects them. */
const collecting = defineModule(
	{ name: "collecting", replicaSafe: true, takes: [erasers] },
	(m) => [m.provide(seen).by((c) => c.collect(erasers))],
);
const eraseLockouts = async (app: Assembly, subject: string) => {
	const eraser = app.get(seen).find((e) => e.name === "rate-limit");
	if (eraser === undefined) throw new Error("rate-limit's eraser is not composed");
	return eraser.online(subject, new AbortController().signal);
};

it("names its lockout for erasure: once dropped, a proof answers 503 and no hold is recorded", async () => {
	const s = await serve({}, [collecting]);
	const { secret } = await s.enrollCode("ann");
	const failing = await s.heldLogin("ann");
	const wrong = { transaction_id: failing.tx, factor_id: failing.factor(), proof: "x:1" };
	expect((await s.call("POST", "/session/mfa/verify", wrong, { jar: failing.jar })).status).toBe(
		401,
	);
	const erased = await eraseLockouts(s.app, "ann");
	expect(erased.reports).toEqual([{ kind: "forgotten", space: "rate-limit.lockouts", removed: 1 }]);
	const { tx, factor, jar } = await s.heldLogin("ann");
	s.events.length = 0;
	for (const proof of ["x:2", `${secret}:3`]) {
		const answer = await s.call(
			"POST",
			"/session/mfa/verify",
			{ transaction_id: tx, factor_id: factor(), proof },
			{ jar },
		);
		expect(answer.status, proof).toBe(503);
	}
	expect(s.events.filter((e) => e.kind.startsWith("mfa.locked"))).toEqual([]);
});

it("answers 503 to a release on a dropped key, a defensive path: for an erased subject the revocation check stops it first", async () => {
	const s = await serve({}, [collecting]);
	const { done } = await s.enrollCode("bea");
	const codes = (done.body.recovery_codes ?? []) as string[];
	const { tx, factor, jar } = await s.heldLogin("bea");
	const proof = { transaction_id: tx, factor_id: factor("backup"), proof: codes[0] ?? "" };
	expect((await s.call("POST", "/session/mfa/verify", proof, { jar })).status).toBe(200);
	await eraseLockouts(s.app, "bea");
	const released = await s.call("POST", "/session/mfa/lock/release", {}, { jar });
	expect(released.status).toBe(503);
	expect(s.events.filter((e) => e.kind === "mfa.lock.recovered")).toEqual([]);
});
