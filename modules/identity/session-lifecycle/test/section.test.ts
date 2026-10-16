import { describe, expect, it } from "vitest";
import { section } from "../src/section.ts";

describe("session-lifecycle's section", () => {
	it.each([
		["lifetime-seconds", 60, 30 * 86_400],
		["sweep-seconds", 1, 3600],
		["credentials-seconds", 30, 3600],
	])("takes %s from %i to %i, and nothing outside", (key, low, high) => {
		const parses = (value: number) => section.safeParse({ [key]: value }).success;
		expect([parses(low - 1), parses(low), parses(high), parses(high + 1)]).toEqual([
			false,
			true,
			true,
			false,
		]);
	});

	it("lasts a session an hour and sweeps every 30 seconds where nothing is set", () => {
		expect(section.parse({})).toMatchObject({ "lifetime-seconds": 3600, "sweep-seconds": 30 });
	});

	it("gives a sign-in 300 seconds to change credentials, where no requirement judges that", () => {
		expect(section.parse({})["credentials-seconds"]).toBe(300);
	});
});
