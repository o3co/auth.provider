import { isUnavailable, Unavailable } from "@mod/kernel";
import { witnessStandIn } from "@mod/mfa-witness/testing";
import { describe, expect, it } from "vitest";
import { backfillWith, settlingOf } from "../src/witnessing.ts";

/**
 * A witness offering withdraw, with the subject's counting factors read in turn from `reads`;
 * `afterRead` runs after the n-th read has taken its answer, as a request racing it would.
 */
const over = (reads: boolean[], afterRead?: (n: number) => void) => {
	const stand = witnessStandIn();
	const asked: string[] = [];
	const { clear, withdraw } = stand.witness;
	stand.witness.clear = async (subject) => {
		asked.push("clear");
		await clear(subject);
	};
	stand.witness.withdraw = async (subject, token) => {
		asked.push(`withdraw ${token}`);
		await withdraw?.(subject, token);
	};
	let n = 0;
	let tokens = 0;
	const counting = async () => {
		const counts = reads[Math.min(n, reads.length - 1)] ?? false;
		n += 1;
		afterRead?.(n);
		return counts;
	};
	const token = () => `t${++tokens}`;
	return {
		stand,
		asked,
		settle: settlingOf({ witness: stand.witness, counting, token }),
		backfill: backfillWith({ witness: stand.witness, counting, token }),
	};
};

describe("settle over a witness offering withdraw", () => {
	it("withdraws only its own mark, leaving the mark a binding set after a reset took its own", async () => {
		const s = over([true, false, true]);
		// A reset takes the factor and this call's mark; a new binding writes its factor and marks it.
		s.stand.next.beforeWithdraw = () => s.stand.marks.set("hal", "binding");
		await s.settle("hal");
		expect([s.stand.marks.get("hal"), s.asked]).toEqual(["binding", ["withdraw t1"]]);
	});

	it("keeps no token where its enroll answered another's mark, so it never removes that mark", async () => {
		const s = over([true, false]);
		// A binding marks first; this call's enroll then answers that the mark is not its token's.
		s.stand.next.beforeEnroll = () => s.stand.marks.set("joy", "binding");
		await s.settle("joy");
		expect([s.stand.marks.get("joy"), s.asked]).toEqual(["binding", []]);
	});

	it("marks anew after withdrawing its own mark that a binding took for its own, by enroll or by read alone", async () => {
		// The second read saw nothing counting, from before the binding wrote; the third sees its factor.
		const s = over([true, false, true]);
		await s.settle("ivy");
		expect([s.stand.marks.get("ivy"), s.asked]).toEqual(["t2", ["withdraw t1"]]);
	});

	it("is unavailable where its withdraw stays unavailable, sent again with the same token first", async () => {
		const s = over([true, false, true]);
		s.stand.failing.withdraw = 4;
		await expect(s.settle("kim")).rejects.toSatisfy(isUnavailable);
		expect([s.stand.marks.get("kim"), s.asked]).toEqual(["t1", Array(4).fill("withdraw t1")]);
	});

	it("is unavailable where the factors cannot be read again after its withdraw", async () => {
		const s = over([true, false]);
		const settle = settlingOf({
			witness: s.stand.witness,
			counting: async () => {
				if (s.asked.length > 0) throw new Unavailable("mfa");
				return s.stand.marks.size === 0;
			},
			token: () => "t1",
		});
		await expect(settle("lou")).rejects.toSatisfy(isUnavailable);
		expect(s.stand.marks.has("lou")).toBe(false);
	});

	it("is unavailable, with no mark, where it reaches its last mark while they still differ", async () => {
		// Each read that sees a factor is followed by a reset; each after its withdraw sees a factor.
		const s = over([true, false, true, false, true, false, true]);
		await expect(s.settle("max")).rejects.toSatisfy(isUnavailable);
		expect(s.stand.marks.has("max")).toBe(false);
	});

	it("retries a withdraw unavailable with the same token, as a lost answer is safe to send again", async () => {
		const s = over([true, false, false]);
		s.stand.lost.withdraw = 1;
		await s.settle("ned");
		expect([s.stand.marks.has("ned"), s.asked]).toEqual([false, ["withdraw t1", "withdraw t1"]]);
	});

	it("leaves a binding's mark set between a withdraw whose answer is lost and its retry", async () => {
		const s = over([true, false, true]);
		const sent = s.stand.witness.withdraw;
		let first = true;
		s.stand.witness.withdraw = async (subject, token) => {
			await sent?.(subject, token);
			if (!first) return;
			// The withdraw took effect, its answer is lost, and a binding marks before the retry.
			first = false;
			s.stand.marks.set("oz", "binding");
			throw new Unavailable("enrollment-witness");
		};
		await s.settle("oz");
		expect(s.stand.marks.get("oz")).toBe("binding");
	});
});

describe("backfill over a witness offering withdraw", () => {
	it("reports a mark another left beside nothing counting after its withdraw, not none", async () => {
		const s = over([true, false, false]);
		// A reset takes the factors and this call's mark; a binding marks, and its factor is lost.
		s.stand.next.beforeWithdraw = () => s.stand.marks.set("ann", "t3");
		expect(await s.backfill("ann")).toBe("inconsistent");
		expect([s.stand.marks.get("ann"), s.asked]).toEqual(["t3", ["withdraw t1"]]);
	});

	it("answers none where its withdraw leaves no mark beside nothing counting", async () => {
		const s = over([true, false, false]);
		expect(await s.backfill("bob")).toBe("none");
		expect(s.stand.marks.has("bob")).toBe(false);
	});

	it("is unavailable, never none, where the witness cannot be read after its withdraw", async () => {
		const s = over([true, false, false]);
		s.stand.next.beforeWithdraw = () => {
			s.stand.failing.read = 1;
		};
		await expect(s.backfill("cid")).rejects.toSatisfy(isUnavailable);
	});

	it("marks anew after withdrawing its own mark that a binding took for its own", async () => {
		const s = over([true, false, true]);
		expect(await s.backfill("dee")).toBe("marked");
		expect([s.stand.marks.get("dee"), s.asked]).toEqual(["t2", ["withdraw t1"]]);
	});

	it("keeps no token where its enroll answered another's mark, and reports that mark as it stands", async () => {
		const s = over([true, false]);
		s.stand.next.beforeEnroll = () => s.stand.marks.set("eve", "binding");
		expect(await s.backfill("eve")).toBe("inconsistent");
		expect([s.stand.marks.get("eve"), s.asked]).toEqual(["binding", []]);
	});
});
