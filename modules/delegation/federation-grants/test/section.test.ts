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
				window: "10s",
			}),
		).toMatchObject({
			"default-lifetime": 604_800,
			"max-lifetime": 7_776_000,
			"connect-lifetime": 300,
			"refresh-before": 60,
			"rotation-window": 7200,
			"lodge-window": 30,
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
			"sweep-interval": 3600,
			"keep-on-subject-revocation": false,
			"identity-check": "required",
			requests: 60,
			window: 60,
		});
	});

	it.each(times)("gives %s's default as an operator writes it", (key, _low, _high, written) => {
		expect(section.parse({})[key]).toBe(section.parse({ [key]: written })[key]);
	});

	it.each([
		"default-seconds",
		"max-seconds",
		"connect-seconds",
		"refresh-before-seconds",
		"rotation-window-seconds",
		"lodge-window-seconds",
		"revocation-skew-seconds",
		"window-seconds",
	])("refuses %s, a name in seconds it no longer reads", (old) => {
		expect(section.safeParse({ [old]: 60 }).error?.issues).toMatchObject([
			{ code: "unrecognized_keys", keys: [old] },
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

	it("refuses a connection without it", () => {
		expect(section.safeParse(withConnection({})).error?.issues).toMatchObject([
			{ path: [...where, key] },
		]);
	});

	it("refuses revocation-skew, an allowance for hosts' clocks it no longer takes", () => {
		expect(section.safeParse({ "revocation-skew": "1s" }).error?.issues).toMatchObject([
			{ code: "unrecognized_keys", keys: ["revocation-skew"] },
		]);
	});

	it("refuses max-access-token-seconds, a name in seconds it no longer reads", () => {
		expect(
			section.safeParse(withConnection({ [key]: "1h", [old]: 3600 })).error?.issues,
		).toMatchObject([{ code: "unrecognized_keys", path: where, keys: [old] }]);
	});
});
