import { isUnavailable } from "@mod/kernel";
import { passkeyWitnessStandIn } from "@mod/passkey-witness/testing";
import { expect, it } from "vitest";
import { backfillWith } from "../src/backfill.ts";

type Holding = "passkey" | "pending" | "none";

/** A backfill over a witness in memory, what passkeys holds as written scripted: `holding` answers in turn, the last one standing. */
function over(...holding: Holding[]) {
	const stand = passkeyWitnessStandIn();
	const answers = [...holding];
	const reads: Holding[] = [];
	let n = 0;
	const settle = backfillWith({
		witness: stand.witness,
		holding: async () => {
			const next = answers.length > 1 ? (answers.shift() as Holding) : (answers[0] ?? "none");
			reads.push(next);
			return next;
		},
		token: () => `t${++n}`,
	});
	return { stand, settle, reads };
}

it("marks a subject holding a passkey with no mark, under its own token, after reading again", async () => {
	const b = over("passkey");
	expect(await b.settle("sam")).toBe("marked");
	expect(b.stand.marks.get("sam")).toBe("t1");
	expect(b.reads).toEqual(["passkey", "passkey"]);
});

it("answers held for a mark already there, setting none", async () => {
	const b = over("passkey");
	b.stand.marks.set("sam", "theirs");
	expect(await b.settle("sam")).toBe("held");
	expect(b.stand.marks.get("sam")).toBe("theirs");
});

it("answers none where neither a passkey nor a mark is there", async () => {
	expect(await over("none").settle("sam")).toBe("none");
});

it("answers pending where only pending ones are written, the mark as it is", async () => {
	const unmarked = over("pending");
	expect(await unmarked.settle("sam")).toBe("pending");
	expect(unmarked.stand.marks.has("sam")).toBe(false);
	const marked = over("pending");
	marked.stand.marks.set("sam", "theirs");
	expect(await marked.settle("sam")).toBe("pending");
	expect(marked.stand.marks.get("sam")).toBe("theirs");
});

it("answers inconsistent for a mark beside nothing written, leaving it", async () => {
	const b = over("none");
	b.stand.marks.set("sam", "lost");
	expect(await b.settle("sam")).toBe("inconsistent");
	expect(b.stand.marks.get("sam")).toBe("lost");
});

it("withdraws its own mark where a reset took the passkeys meanwhile, answering none", async () => {
	const b = over("passkey", "none");
	expect(await b.settle("sam")).toBe("none");
	expect(b.stand.marks.has("sam")).toBe(false);
});

it("answers held where another's mark won meanwhile", async () => {
	const b = over("passkey");
	b.stand.next.beforeEnroll = () => b.stand.marks.set("sam", "theirs");
	expect(await b.settle("sam")).toBe("held");
	expect(b.stand.marks.get("sam")).toBe("theirs");
});

it("answers inconsistent where another's mark stands beside nothing after its own withdraw", async () => {
	const b = over("passkey", "none");
	b.stand.next.beforeWithdraw = () => {
		b.stand.marks.delete("sam");
		b.stand.marks.set("sam", "theirs");
	};
	expect(await b.settle("sam")).toBe("inconsistent");
	expect(b.stand.marks.get("sam")).toBe("theirs");
});

it("marks anew where a passkey came back after its withdraw, three times at most, then is unavailable", async () => {
	const once = over("passkey", "none", "passkey", "passkey");
	expect(await once.settle("sam")).toBe("marked");
	expect(once.stand.marks.get("sam")).toBe("t2");
	const flapping = over(
		"passkey",
		"none",
		"passkey",
		"none",
		"passkey",
		"none",
		"passkey",
		"none",
		"passkey",
		"none",
	);
	await expect(flapping.settle("sam")).rejects.toSatisfy(isUnavailable);
	expect(flapping.stand.marks.has("sam")).toBe(false);
});

it("is unavailable where its mark is gone though the passkey stands", async () => {
	const b = over("passkey");
	b.stand.next.afterEnroll = () => b.stand.marks.delete("sam");
	await expect(b.settle("sam")).rejects.toSatisfy(isUnavailable);
});

it("is unavailable while the witness cannot be read", async () => {
	const b = over("passkey");
	b.stand.failing.read = 1;
	await expect(b.settle("sam")).rejects.toSatisfy(isUnavailable);
});

it("withdraws by its own token alone, leaving a mark another set in place of its own meanwhile", async () => {
	const b = over("passkey", "none");
	b.stand.next.afterEnroll = () => b.stand.marks.set("sam", "theirs");
	expect(await b.settle("sam")).toBe("inconsistent");
	expect(b.stand.marks.get("sam")).toBe("theirs");
});
