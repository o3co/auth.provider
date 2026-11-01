import { isUnavailable } from "@mod/kernel";
import { witnessStandIn } from "@mod/mfa-witness/testing";
import { expect, it } from "vitest";
import { settlingOf } from "../src/witnessing.ts";

// These hold settle over a witness with no withdraw, whose own clear may take any mark; the
// withdraw it uses where offered is in withdraw.test.ts.
const witnessStandInWithout = () => witnessStandIn("enrollment-witness", { withdraw: false });

/** Settling over a witness in memory, the subject's counting factors read in turn from `reads`. */
const settled = (reads: boolean[]) => {
	const stand = witnessStandInWithout();
	let n = 0;
	const settle = settlingOf({
		witness: stand.witness,
		counting: async () => reads[Math.min(n++, reads.length - 1)] ?? false,
		token: () => `t${n}`,
	});
	return { settle, marks: stand.marks, stand };
};

it("marks a subject holding a counting factor with no mark, and leaves one already marked", async () => {
	const { settle, marks } = settled([true]);
	await settle("ann");
	expect(marks.has("ann")).toBe(true);
	marks.set("bob", "other");
	await settle("bob");
	expect(marks.get("bob")).toBe("other");
});

it("clears a mark it set itself when the factor went meanwhile, as a reset's removal does", async () => {
	const { settle, marks } = settled([true, false]);
	await settle("cid");
	expect(marks.has("cid")).toBe(false);
});

it("marks anew when its clear takes the mark a new binding set after a reset", async () => {
	const stand = witnessStandInWithout();
	const reads = [true, false, true, true];
	let n = 0;
	const settle = settlingOf({
		witness: stand.witness,
		counting: async () => {
			const counts = reads[Math.min(n++, reads.length - 1)] ?? false;
			// After the late read that sees the reset, a new binding writes its factor and marks it.
			if (n === 2) stand.marks.set("hal", "binding");
			return counts;
		},
		token: () => `t${n}`,
	});
	// A reset takes the factor and the mark right after this call marks.
	stand.next.afterEnroll = () => stand.marks.delete("hal");
	await settle("hal");
	expect(stand.marks.has("hal")).toBe(true);
});

it("checks the last mark it may make, and clears it where a reset took the factor meanwhile", async () => {
	const stand = witnessStandInWithout();
	const reads = [true, false, true, false, false];
	let n = 0;
	const settle = settlingOf({
		witness: stand.witness,
		counting: async () => {
			const counts = reads[Math.min(n++, reads.length - 1)] ?? false;
			// A new binding marks after the second read; a reset takes the mark after the third.
			if (n === 2 && !stand.marks.has("ivy")) stand.marks.set("ivy", "binding");
			if (n === 3) stand.marks.delete("ivy");
			return counts;
		},
		token: () => `t${n}`,
	});
	// A reset takes the factor and the mark right after this call first marks.
	stand.next.afterEnroll = () => stand.marks.delete("ivy");
	await settle("ivy");
	expect(stand.marks.has("ivy")).toBe(false);
});

it("never clears a mark another set after its own clear, though it marked before", async () => {
	const stand = witnessStandInWithout();
	const reads = [true, false, true, false, false];
	let n = 0;
	const settle = settlingOf({
		witness: stand.witness,
		counting: async () => {
			const counts = reads[Math.min(n++, reads.length - 1)] ?? false;
			// After this call clears its own mark, a new binding writes its factor and marks it first.
			if (n === 3) stand.marks.set("joy", "binding");
			return counts;
		},
		token: () => `t${n}`,
	});
	// A reset takes the factor, not yet the mark; then the store loses the new binding's factor.
	await settle("joy");
	expect(stand.marks.get("joy")).toBe("binding");
});

it("never clears a mark it did not set, which may be a store that lost its factors", async () => {
	const { settle, marks } = settled([false]);
	marks.set("dee", "theirs");
	await settle("dee");
	expect(marks.get("dee")).toBe("theirs");
});

it("is unavailable while the mark and the factors still differ after it settled twice", async () => {
	// A witness that takes every mark and never shows one.
	const blind = { read: async () => false, enroll: async () => true, clear: async () => {} };
	const settle = settlingOf({ witness: blind, counting: async () => true, token: () => "t" });
	await expect(settle("eli")).rejects.toSatisfy(isUnavailable);
});

it("does nothing without a witness", async () => {
	const settle = settlingOf({ witness: undefined, counting: async () => true, token: () => "t" });
	await expect(settle("fay")).resolves.toBeUndefined();
});

it("is unavailable when the witness cannot be read", async () => {
	const { settle, stand } = settled([true]);
	stand.failing.read = 1;
	await expect(settle("gus")).rejects.toSatisfy(isUnavailable);
});
