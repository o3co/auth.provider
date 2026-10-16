import { describe, expect, it } from "vitest";
import { sharedRounds } from "../src/rounds.ts";

describe("shared confirmation rounds", () => {
	it("lets calls during a round share the next one, never the running one", async () => {
		const starts: number[] = [];
		let release: () => void = () => {};
		const confirm = sharedRounds(async () => {
			starts.push(starts.length + 1);
			await new Promise<void>((resolve) => {
				release = resolve;
			});
			return starts.length;
		});
		const first = confirm();
		const late = [confirm(), confirm(), confirm()];
		expect(starts).toEqual([1]);
		release();
		expect(await first).toBe(1);
		await new Promise((r) => setTimeout(r, 0));
		expect(starts).toEqual([1, 2]);
		release();
		expect(await Promise.all(late)).toEqual([2, 2, 2]);
	});

	it("starts afresh after a failed round", async () => {
		let n = 0;
		const confirm = sharedRounds(async () => {
			n += 1;
			if (n === 1) throw new Error("down");
			return n;
		});
		await expect(confirm()).rejects.toThrow("down");
		expect(await confirm()).toBe(2);
	});
});
