import { describe, expect, it } from "vitest";
import { section } from "../src/section.ts";

describe("session-tokens-store section", () => {
	it("keeps 1,000 references to a session, and lists sessions pending a push-out over 64 shards of 1,000, unless told otherwise", () => {
		expect(section.parse({})).toEqual({
			"references-per-session": 1000,
			"pending-shards": 64,
			"pending-per-shard": 1000,
		});
	});

	it("refuses sizes out of range", () => {
		for (const bad of [
			{ "references-per-session": 0 },
			{ "references-per-session": 10_001 },
			{ "references-per-session": 1.5 },
			{ "pending-shards": 0 },
			{ "pending-shards": 65_537 },
			{ "pending-per-shard": 0 },
			{ "pending-per-shard": 10_001 },
		]) {
			expect(section.safeParse(bad).success).toBe(false);
		}
		expect(
			section.parse({
				"references-per-session": 10_000,
				"pending-shards": 65_536,
				"pending-per-shard": 10_000,
			}),
		).toEqual({
			"references-per-session": 10_000,
			"pending-shards": 65_536,
			"pending-per-shard": 10_000,
		});
	});
});
