import { describe, expect, it } from "vitest";
import { section } from "../src/section.ts";

describe("session-store section", () => {
	it("spreads the list over 1,024 shards of 1,000, and lists 100 sessions a subject, unless told otherwise", () => {
		expect(section.parse({})).toEqual({
			"closing-shards": 1024,
			"closings-per-shard": 1000,
			"sessions-per-subject": 100,
		});
	});

	it("refuses sizes out of range", () => {
		for (const bad of [
			{ "closing-shards": 0 },
			{ "closing-shards": 65_537 },
			{ "closings-per-shard": 0 },
			{ "closings-per-shard": 10_001 },
			{ "closing-shards": 1.5 },
			{ "sessions-per-subject": 0 },
			{ "sessions-per-subject": 10_001 },
		]) {
			expect(section.safeParse(bad).success).toBe(false);
		}
		expect(
			section.parse({
				"closing-shards": 65_536,
				"closings-per-shard": 10_000,
				"sessions-per-subject": 10_000,
			}),
		).toBeDefined();
	});
});
