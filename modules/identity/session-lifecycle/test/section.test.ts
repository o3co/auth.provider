import { sessionRules } from "@mod/session";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defaultLifetimeSeconds } from "../src/limits.ts";
import { section } from "../src/section.ts";

const keys = ["lifetime", "sweep-interval", "credentials-within"] as const;

describe("session-lifecycle's section", () => {
	it("reads each key written with its unit, as seconds", () => {
		expect(
			section.parse({ lifetime: "8h", "sweep-interval": "1m", "credentials-within": "10m" }),
		).toEqual({ lifetime: 28_800, "sweep-interval": 60, "credentials-within": 600 });
	});

	it.each(keys)("refuses %s as a bare number, or a string of digits only", (key) => {
		expect(section.safeParse({ [key]: 60 }).success).toBe(false);
		expect(section.safeParse({ [key]: "60" }).success).toBe(false);
	});

	it.each([
		["lifetime", 60, 30 * 86_400],
		["sweep-interval", 1, 3600],
		["credentials-within", 30, 3600],
	])("takes %s from %is to %is, and nothing outside", (key, low, high) => {
		const parses = (seconds: number) => section.safeParse({ [key]: `${seconds}s` }).success;
		expect([parses(low - 1), parses(low), parses(high), parses(high + 1)]).toEqual([
			false,
			true,
			true,
			false,
		]);
	});

	it("lasts a session an hour, sweeps every 30 seconds and gives a sign-in 300 seconds to change credentials, where nothing is set", () => {
		expect(section.parse({})).toEqual({
			lifetime: 3600,
			"sweep-interval": 30,
			"credentials-within": 300,
		});
	});

	it("writes each default as an operator writes it, reading to the constant it stands for", () => {
		const { properties } = z.toJSONSchema(section, { io: "input" }) as {
			properties: Record<(typeof keys)[number], { default: unknown }>;
		};
		const readOf = (key: (typeof keys)[number]) =>
			section.parse({ [key]: properties[key].default })[key];
		expect(keys.map((key) => properties[key].default)).toEqual(["1h", "30s", "5m"]);
		expect(readOf("lifetime")).toBe(defaultLifetimeSeconds);
		expect(readOf("sweep-interval")).toBe(30);
		expect(readOf("credentials-within")).toBe(sessionRules.credentialsSecondsDefault);
	});
});

describe("session-lifecycle's section, under the names in seconds", () => {
	const renamed = [
		["lifetime-seconds", "lifetime", 60, 30 * 86_400],
		["sweep-seconds", "sweep-interval", 1, 3600],
		["credentials-seconds", "credentials-within", 30, 3600],
	] as const;

	it("still reads each name in seconds, alone, as its name without a unit", () => {
		expect(
			section.parse({
				"lifetime-seconds": 120,
				"sweep-seconds": 1,
				"credentials-seconds": 60,
			}),
		).toEqual({ lifetime: 120, "sweep-interval": 1, "credentials-within": 60 });
	});

	it.each(renamed)(
		"takes %s, read as %s, from %i to %i, and nothing outside",
		(old, _now, low, high) => {
			const parses = (value: number) => section.safeParse({ [old]: value }).success;
			expect([parses(low - 1), parses(low), parses(high), parses(high + 1)]).toEqual([
				false,
				true,
				true,
				false,
			]);
		},
	);

	it.each(renamed)("refuses %s given beside %s, naming the key to keep", (old, now) => {
		const read = section.safeParse({ [old]: 60, [now]: "1m" });
		expect(read.success).toBe(false);
		expect(read.error?.issues).toEqual([
			expect.objectContaining({ path: [old], message: expect.stringContaining(now) }),
		]);
	});
});
