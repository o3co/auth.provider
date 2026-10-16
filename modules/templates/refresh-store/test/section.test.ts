import { describe, expect, it } from "vitest";
import { section } from "../src/section.ts";

describe("refresh-store section", () => {
	it("keeps 1,000 to a list, and spreads settling over 1,024 shards of 1,000, unless told otherwise", () => {
		expect(section.parse({})).toEqual({
			"families-per-session": 1000,
			"tokens-per-family": 1000,
			"settle-shards": 1024,
			"settles-per-shard": 1000,
		});
	});

	it("refuses sizes out of range", () => {
		for (const bad of [
			{ "families-per-session": 0 },
			{ "families-per-session": 10_001 },
			{ "tokens-per-family": 0 },
			{ "tokens-per-family": 10_001 },
			{ "settle-shards": 0 },
			{ "settle-shards": 65_537 },
			{ "settles-per-shard": 0 },
			{ "settles-per-shard": 10_001 },
			{ "settle-shards": 1.5 },
		]) {
			expect(section.safeParse(bad).success).toBe(false);
		}
		const widest = {
			"families-per-session": 10_000,
			"tokens-per-family": 10_000,
			"settle-shards": 65_536,
			"settles-per-shard": 10_000,
		};
		expect(section.parse(widest)).toEqual(widest);
	});
});
