import { isUnavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import type { AfterReset } from "@mod/mfa-extensions";
import { witnessStandIn } from "@mod/mfa-witness/testing";
import { describe, expect, it } from "vitest";
import { backfillWith, witnessingWith } from "../src/witnessing.ts";
import { witnessed } from "./harness.ts";

/**
 * The bridge over a witness offering withdraw and markedWith, a reset's `after` answering in turn
 * from `answers` (the last repeated), and the reads of the mark's token counted.
 */
const over = (answers: AfterReset[], options: { readonly withdraw?: boolean } = {}) => {
	const stand = witnessStandIn("enrollment-witness", options);
	const recorded: unknown[] = [];
	const logged = recordingLog();
	let tokens = 0;
	const told = witnessingWith({
		witness: stand.witness,
		audit: { record: async (event) => void recorded.push(event) },
		log: logged.log,
		token: () => `r${++tokens}`,
	});
	const read = { markedWith: 0, after: 0 };
	const markedWith = stand.witness.markedWith;
	if (markedWith) {
		stand.witness.markedWith = async (subject) => {
			read.markedWith += 1;
			return markedWith(subject);
		};
	}
	const after = async () => {
		const answer = answers[Math.min(read.after, answers.length - 1)] ?? "none";
		read.after += 1;
		return answer;
	};
	return { stand, told, after, read, recorded, logged };
};

describe("cleared, after a reset, over a witness offering withdraw", () => {
	it("does nothing where no mark stands, reading nothing after", async () => {
		const { told, after, read } = over(["none"]);
		await told.cleared("ann", after);
		expect(read).toEqual({ markedWith: 1, after: 0 });
	});

	it("leaves the mark where a factor stands since the reset, as a binding after it set or took it", async () => {
		const { stand, told, after } = over(["counting"]);
		stand.marks.set("ann", "t2");
		await told.cleared("ann", after);
		expect(stand.marks.get("ann")).toBe("t2");
	});

	it("withdraws the mark it read where none stands, and reads after again", async () => {
		const { stand, told, after, read } = over(["none"]);
		stand.marks.set("ann", "t-old");
		await told.cleared("ann", after);
		expect(stand.marks.has("ann")).toBe(false);
		expect(read).toEqual({ markedWith: 1, after: 2 });
	});

	it("sends its withdraw again with the token it read, never reading again, so a mark set meanwhile stays", async () => {
		const { stand, told, after, read } = over(["none"]);
		stand.marks.set("ann", "t-old");
		// The first withdraw takes the old mark and its answer is lost; a binding marks before the second.
		stand.lost.withdraw = 1;
		stand.next.beforeWithdraw = () => {
			stand.next.beforeWithdraw = () => stand.marks.set("ann", "t2");
		};
		await told.cleared("ann", after);
		expect(stand.marks.get("ann")).toBe("t2");
		expect(read.markedWith).toBe(1);
	});

	it("leaves the mark where what stands is unsure, recording it at the reset and answering unavailable", async () => {
		const { stand, told, after, recorded, logged } = over(["unsure"]);
		stand.marks.set("ann", "t2");
		await expect(told.cleared("ann", after)).rejects.toSatisfy(isUnavailable);
		expect(stand.marks.get("ann")).toBe("t2");
		expect(recorded).toEqual([
			{ kind: "mfa.enrollment_inconsistent", subject: "ann", attributes: { at: "reset" } },
		]);
		expect(logged.lines().map((line) => [line.event, line.fields])).toEqual([
			["mfa.enrollment_inconsistent", { at: "reset" }],
		]);
	});

	it("marks anew after its withdraw where a binding wrote a factor and relied on the old mark meanwhile", async () => {
		const { stand, told, after } = over(["none", "counting"]);
		stand.marks.set("ann", "t-old");
		await told.cleared("ann", after);
		expect(stand.marks.get("ann")).toBe("r1");
	});

	it("records and answers unavailable where what stands after its withdraw is unsure, the mark gone", async () => {
		const { stand, told, after, recorded } = over(["none", "unsure"]);
		stand.marks.set("ann", "t-old");
		await expect(told.cleared("ann", after)).rejects.toSatisfy(isUnavailable);
		expect(stand.marks.has("ann")).toBe(false);
		expect(recorded).toHaveLength(1);
	});

	it("given no after, withdraws the mark it read, and so never takes one set after its read", async () => {
		const { stand, told } = over([]);
		stand.marks.set("ann", "t-old");
		stand.next.beforeWithdraw = () => stand.marks.set("ann", "t2");
		await told.cleared("ann");
		expect(stand.marks.get("ann")).toBe("t2");
	});

	it("clears over a witness offering no withdraw, as before", async () => {
		const { stand, told, after, read } = over(["counting"], { withdraw: false });
		stand.marks.set("ann", "t2");
		await told.cleared("ann", after);
		expect([stand.marks.has("ann"), read.after]).toEqual([false, 0]);
	});
});

describe("after a reset answered unavailable, the state is found by backfill, and a reset again mends it", () => {
	const standing = (value: () => "counting" | "unclaimed" | "none") => async () => value();

	it("a withdraw done with its answer lost, and every retry failing: no mark, and backfill finds none", async () => {
		const { stand, told, after } = over(["none"]);
		stand.marks.set("ann", "t-old");
		// The first withdraw takes the mark and its answer is lost; every retry after it fails.
		stand.lost.withdraw = 1;
		stand.next.beforeWithdraw = () => {
			stand.failing.withdraw = 3;
		};
		await expect(told.cleared("ann", after)).rejects.toSatisfy(isUnavailable);
		expect(stand.marks.has("ann")).toBe(false);
		const backfill = backfillWith({
			witness: stand.witness,
			standing: standing(() => "none"),
			token: () => "b",
		});
		expect(await backfill("ann")).toBe("none");
	});

	it("a mark made anew, a reset since, and its own withdraw failing: a mark alone, inconsistent, then mended by a reset", async () => {
		let held: "counting" | "none" = "counting";
		const { stand, told } = over([]);
		stand.marks.set("ann", "t-old");
		// What stands: none at the reset's read, a binding's factor at its read after, then another reset.
		const answers: AfterReset[] = ["none", "counting", "counting", "none"];
		let n = 0;
		const after = async () => {
			const answer = answers[Math.min(n, answers.length - 1)] ?? "none";
			n += 1;
			if (n === answers.length) held = "none";
			return answer;
		};
		stand.next.afterEnroll = () => {
			stand.failing.withdraw = 4;
		};
		await expect(told.cleared("ann", after)).rejects.toSatisfy(isUnavailable);
		expect(stand.marks.get("ann")).toBe("r1");
		const backfill = backfillWith({
			witness: stand.witness,
			standing: standing(() => held),
			token: () => "b",
		});
		expect(await backfill("ann")).toBe("inconsistent");
		await told.cleared("ann", async () => "none");
		expect(await backfill("ann")).toBe("none");
	});
});

describe("backfill beside a factor written and not claimed", () => {
	it("answers unclaimed, leaving the mark or its absence as it is", async () => {
		const stand = witnessStandIn();
		const backfill = backfillWith({
			witness: stand.witness,
			standing: async () => "unclaimed",
			token: () => "b",
		});
		expect(await backfill("ann")).toBe("unclaimed");
		expect(stand.marks.has("ann")).toBe(false);
		stand.marks.set("bob", "t");
		expect(await backfill("bob")).toBe("unclaimed");
		expect(stand.marks.get("bob")).toBe("t");
	});

	it("keeps the mark it set where the factor's claim is lost before it reads again", async () => {
		const stand = witnessStandIn();
		const reads: ("counting" | "unclaimed")[] = ["counting", "unclaimed"];
		let n = 0;
		const backfill = backfillWith({
			witness: stand.witness,
			standing: async () => reads[Math.min(n++, reads.length - 1)] ?? "unclaimed",
			token: () => "b",
		});
		expect(await backfill("ann")).toBe("unclaimed");
		expect(stand.marks.get("ann")).toBe("b");
	});
});

describe("a reset that stops before it reads the mark, with mfa", () => {
	/** Holds the next read of the mark's token until the answer is called, as a reset stopped there would. */
	const stopping = (witness: ReturnType<typeof witnessStandIn>) => {
		let go: (() => void) | undefined;
		witness.next.beforeMarkedWith = () =>
			new Promise<void>((resume) => {
				go = resume;
			});
		// Goes on, once it stopped there: a reset that never reads the mark's token never stops.
		return () => {
			expect(go, "the reset stopped before it read the mark").toBeDefined();
			go?.();
		};
	};

	it("leaves the mark a binding set after another reset finished, once it goes on", async () => {
		const { decided, bindCode, witness, counted } = await witnessed();
		await bindCode("kim");
		const resume = stopping(witness);
		const first = decided.clear("kim");
		await decided.clear("kim");
		await bindCode("kim");
		const mark = witness.marks.get("kim");
		resume();
		await first;
		expect([await counted("kim"), witness.marks.get("kim")]).toEqual([1, mark]);
	});

	it("leaves the mark, recorded and unavailable, where the store lost the subject's records meanwhile", async () => {
		const { decided, bindCode, witness, place, events } = await witnessed();
		await bindCode("lou");
		const resume = stopping(witness);
		const first = decided.clear("lou");
		await decided.clear("lou");
		await bindCode("lou");
		const mark = witness.marks.get("lou");
		place.wipe();
		resume();
		await expect(first).rejects.toSatisfy(isUnavailable);
		expect(witness.marks.get("lou")).toBe(mark);
		expect(events.map((e) => [e.kind, e.attributes])).toContainEqual([
			"mfa.enrollment_inconsistent",
			{ at: "reset" },
		]);
		// The reset run again, its fence the store's own now, takes the mark.
		await decided.clear("lou");
		expect(witness.marks.has("lou")).toBe(false);
	});
});
