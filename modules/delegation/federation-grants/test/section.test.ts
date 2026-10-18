import { describe, expect, it } from "vitest";
import { section } from "../src/section.ts";

/** Each time key, from its least to its most in seconds, and its default as an operator writes it. */
const times = [
	["default-lifetime", 60, 31_536_000, "30d"],
	["max-lifetime", 60, 31_536_000, "30d"],
	["connect-lifetime", 60, 3600, "10m"],
	["refresh-before", 0, 3600, "30s"],
	["rotation-window", 1, 86_400, "1h"],
	["lodge-window", 1, 86_400, "1m"],
	["revocation-skew", 0, 300, "1s"],
	["window", 1, 3600, "1m"],
] as const;

describe("federation-grants' section: its times", () => {
	it("reads each time written with its unit, as seconds", () => {
		expect(
			section.parse({
				"default-lifetime": "7d",
				"max-lifetime": "90d",
				"connect-lifetime": "5m",
				"refresh-before": "1m",
				"rotation-window": "2h",
				"lodge-window": "30s",
				"revocation-skew": "2s",
				window: "10s",
			}),
		).toMatchObject({
			"default-lifetime": 604_800,
			"max-lifetime": 7_776_000,
			"connect-lifetime": 300,
			"refresh-before": 60,
			"rotation-window": 7200,
			"lodge-window": 30,
			"revocation-skew": 2,
			window: 10,
		});
	});

	it.each(times)("refuses %s as a bare number, or a string of digits only", (key) => {
		expect(section.safeParse({ [key]: 60 }).error?.issues).toMatchObject([{ path: [key] }]);
		expect(section.safeParse({ [key]: "60" }).error?.issues).toMatchObject([
			{ path: [key], params: { problem: "missing-unit" } },
		]);
	});

	it.each(times)("takes %s from %is to %is, and nothing outside", (key, low, high) => {
		const parses = (seconds: number) => section.safeParse({ [key]: `${seconds}s` }).success;
		const below = low === 0 ? "-1s" : `${low - 1}s`;
		expect([
			section.safeParse({ [key]: below }).success,
			parses(low),
			parses(high),
			parses(high + 1),
		]).toEqual([false, true, true, false]);
	});

	it("reads an empty section with the defaults it had", () => {
		expect(section.parse({})).toEqual({
			connections: {},
			"default-lifetime": 2_592_000,
			"max-lifetime": 2_592_000,
			"connect-lifetime": 600,
			"refresh-before": 30,
			rotations: 24,
			"rotation-window": 3600,
			lodges: 60,
			"lodge-window": 60,
			"revocation-skew": 1,
			"keep-on-subject-revocation": false,
			"identity-check": "required",
			requests: 60,
			window: 60,
		});
	});

	it.each(times)("gives %s's default as an operator writes it", (key, _low, _high, written) => {
		expect(section.parse({})[key]).toBe(section.parse({ [key]: written })[key]);
	});
});

describe("federation-grants' section, under the names in seconds", () => {
	/** Each name in seconds, the name it gives way to, and its bounds. */
	const renamed = [
		["default-seconds", "default-lifetime", 60, 31_536_000],
		["max-seconds", "max-lifetime", 60, 31_536_000],
		["connect-seconds", "connect-lifetime", 60, 3600],
		["refresh-before-seconds", "refresh-before", 0, 3600],
		["rotation-window-seconds", "rotation-window", 1, 86_400],
		["lodge-window-seconds", "lodge-window", 1, 86_400],
		["revocation-skew-seconds", "revocation-skew", 0, 300],
		["window-seconds", "window", 1, 3600],
	] as const;

	it.each(renamed)("still reads %s, alone, as %s", (old, now, low) => {
		const read = section.parse({ [old]: low });
		expect(read[now]).toBe(low);
		expect(read).not.toHaveProperty(old);
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

	it.each(renamed)("refuses %s given beside %s, naming the key to keep", (old, now, low) => {
		const read = section.safeParse({ [old]: low, [now]: `${low}s` });
		expect(read.error?.issues).toEqual([
			expect.objectContaining({ path: [old], message: expect.stringContaining(now) }),
		]);
	});
});

describe("federation-grants' section: a connection's longest access token life", () => {
	const key = "max-access-token-lifetime";
	const old = "max-access-token-seconds";
	const where = ["connections", "cal"];
	/** The section with one connection, `cal`, holding what is given beside its IdP and scopes. */
	const withConnection = (given: Record<string, unknown>) => ({
		connections: { cal: { idp: "corp", scopes: ["openid"], ...given } },
	});
	const lifeOf = (given: Record<string, unknown>) =>
		section.parse(withConnection(given)).connections.cal;

	it("reads it written with its unit, as seconds", () => {
		expect(lifeOf({ [key]: "1h" })?.[key]).toBe(3600);
	});

	it("refuses it as a bare number, or a string of digits only", () => {
		expect(section.safeParse(withConnection({ [key]: 60 })).error?.issues).toMatchObject([
			{ path: [...where, key] },
		]);
		expect(section.safeParse(withConnection({ [key]: "60" })).error?.issues).toMatchObject([
			{ path: [...where, key], params: { problem: "missing-unit" } },
		]);
	});

	it("takes it from 1s to 1d, and nothing outside", () => {
		const parses = (written: string) =>
			section.safeParse(withConnection({ [key]: written })).success;
		expect([parses("0s"), parses("1s"), parses("86400s"), parses("86401s")]).toEqual([
			false,
			true,
			true,
			false,
		]);
	});

	it("refuses a connection that gives it under neither name", () => {
		expect(section.safeParse(withConnection({})).error?.issues).toMatchObject([
			{ path: [...where, key] },
		]);
	});

	it("still reads it in seconds, alone, under its name in seconds", () => {
		const read = lifeOf({ [old]: 3600 });
		expect(read?.[key]).toBe(3600);
		expect(read).not.toHaveProperty(old);
	});

	it("takes the name in seconds from 1 to 86400, and nothing outside", () => {
		const parses = (value: number) => section.safeParse(withConnection({ [old]: value })).success;
		expect([parses(0), parses(1), parses(86_400), parses(86_401)]).toEqual([
			false,
			true,
			true,
			false,
		]);
	});

	it("refuses it given under both names in one connection, naming the key to keep", () => {
		const read = section.safeParse(withConnection({ [old]: 3600, [key]: "1h" }));
		expect(read.error?.issues).toEqual([
			expect.objectContaining({ path: [...where, old], message: expect.stringContaining(key) }),
		]);
	});
});
