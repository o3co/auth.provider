import { expect, it } from "vitest";
import { erasureEnabledFrom, erasureMarks } from "../src/contract.ts";

const holding = (marks: Record<string, unknown>) => ({ control: async () => ({ marks }) });

it("reads erasure as enabled where the mark is there, whatever it holds, and offers nothing without a control record", async () => {
	expect(await erasureEnabledFrom(holding({}))?.erasureEnabled?.()).toBe(false);
	expect(
		await erasureEnabledFrom(holding({ [erasureMarks.enabled]: true })).erasureEnabled?.(),
	).toBe(true);
	expect(
		await erasureEnabledFrom(holding({ [erasureMarks.enabled]: false })).erasureEnabled?.(),
	).toBe(true);
	expect(erasureEnabledFrom(undefined)).toEqual({});
});
