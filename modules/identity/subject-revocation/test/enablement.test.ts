import { Unavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { erasureMark } from "../src/erasure/gate.ts";
import type { BoundaryStore } from "../src/store.ts";

/** A boundary store answering `answers` in turn to whether erasure is enabled, counting the reads. */
function telling(answers: readonly (boolean | "down")[]) {
	let reads = 0;
	const boundaries = {
		erasureEnabled: async () => {
			const answer = answers[Math.min(reads, answers.length - 1)];
			reads += 1;
			if (answer === "down") throw new Unavailable("store");
			return answer === true;
		},
	} as unknown as BoundaryStore;
	return { boundaries, reads: () => reads };
}

it("cannot tell where the store has no reading, known without asking it", async () => {
	const mark = erasureMark({} as BoundaryStore);
	expect(mark.cannotTell).toBe(true);
	expect(await mark.read()).toBe("cannot-tell");
});

it("holds on and off for the process once read", async () => {
	for (const [answer, state] of [
		[true, "on"],
		[false, "off"],
	] as const) {
		const store = telling([answer, !answer]);
		const mark = erasureMark(store.boundaries);
		expect(mark.cannotTell).toBe(false);
		expect(await mark.read()).toBe(state);
		expect(await mark.read()).toBe(state);
		expect(store.reads()).toBe(1);
	}
});

it("answers unread while the store cannot answer, and reads it again the next time", async () => {
	const store = telling(["down", "down", true]);
	const mark = erasureMark(store.boundaries);
	expect(await mark.read()).toBe("unread");
	expect(await mark.read()).toBe("unread");
	expect(await mark.read()).toBe("on");
	expect(store.reads()).toBe(3);
});
