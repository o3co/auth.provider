import { describe, expect, it } from "vitest";
import { section } from "../src/section.ts";

describe("code-grant-store section", () => {
	it("spreads the list over 1,024 shards of 1,000 unless told otherwise", () => {
		expect(section.parse({})).toEqual({ "void-shards": 1024, "voids-per-shard": 1000 });
	});

	it("refuses sizes out of range", () => {
		for (const bad of [
			{ "void-shards": 0 },
			{ "void-shards": 65_537 },
			{ "voids-per-shard": 0 },
			{ "voids-per-shard": 10_001 },
			{ "void-shards": 1.5 },
		]) {
			expect(section.safeParse(bad).success).toBe(false);
		}
		expect(section.parse({ "void-shards": 65_536, "voids-per-shard": 10_000 })).toBeDefined();
	});
});
