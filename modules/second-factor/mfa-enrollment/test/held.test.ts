import { expect, it } from "vitest";
import { heldOf, holding } from "../src/held.ts";

/** A transaction's `keep` over one held value, in use until `ended`. */
const keeping = () => {
	const state: { held?: unknown; ended?: true } = {};
	const keep = async (_id: string, change: (held: unknown) => unknown) => {
		if (state.ended) return undefined;
		const next = change(state.held);
		if (next === undefined) return undefined;
		state.held = next;
		return { held: next };
	};
	return { state, held: holding({ keep }), read: () => heldOf({ held: state.held }) };
};

it("holds a binding only in a transaction still in use, ending the pass it began with", async () => {
	const { state, held, read } = keeping();
	await held.bindingSent("t", { proof: "contact", sealed: "s" });
	await held.bindingPassed("t", "s", { kind: "code", pass: "x" });
	expect(await held.hold("t", "p")).toBe(true);
	expect(read()).toEqual({ pending: "p", proved: true });
	state.ended = true;
	expect(await held.hold("t", "q")).toBe(false);
});

it("keeps a binding proof's pass only over the challenge it answered, which it ends", async () => {
	const { held, read } = keeping();
	await held.bindingSent("t", { proof: "contact", sealed: "s2" });
	const passed = { kind: "code", pass: "pass" };
	expect(await held.bindingPassed("t", "s1", passed)).toBe(false);
	expect(await held.bindingPassed("t", "s2", passed)).toBe(true);
	expect(read()).toEqual({ bindingPassed: passed, proved: true });
});
