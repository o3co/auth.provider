import { describe, expect, it } from "vitest";
import { section } from "../src/section.ts";

const parses = (settings: Record<string, unknown>) => section.safeParse(settings).success;
const idp = (more: Record<string, unknown> = {}) => ({ type: "oidc", ...more });

describe("federation's section", () => {
	it.each([
		["transaction-lifetime", 60, 3600],
		["window", 1, 3600],
	])(
		"takes %s from %is to %is, whole seconds written with their unit, and nothing outside",
		(key, low, high) => {
			const takes = (value: unknown) => parses({ [key]: value });
			const seconds = [low - 1, low, low + 0.5, high, high + 1].map((n) => `${n}s`);
			expect(seconds.map(takes)).toEqual([false, true, false, true, false]);
			expect([low, String(low)].map(takes)).toEqual([false, false]);
		},
	);

	it("takes requests from 1 to 1000, whole, and nothing outside", () => {
		const takes = (value: number) => parses({ requests: value });
		expect([0, 1, 1.5, 1000, 1001].map(takes)).toEqual([false, true, false, true, false]);
	});

	it("takes an IdP name of 1 to 32 lowercase letters, digits and -, not starting with -", () => {
		const named = (name: string) => parses({ idps: { [name]: idp() } });
		expect(["a", "0-a", "a".repeat(32)].map(named)).toEqual([true, true, true]);
		expect(["", "-a", "Ab", "a_b", "a.b", "a!", "a".repeat(33)].map(named)).toEqual(
			Array(7).fill(false),
		);
	});

	it("maps an upstream's amr only to one of ours: 1 to 32 letters, digits, _ and -", () => {
		const mapped = (amr: string) => parses({ idps: { a: idp({ "upstream-amr": { up: amr } }) } });
		expect(["A_b-1", "a".repeat(32)].map(mapped)).toEqual([true, true]);
		expect(["", "a.b", "a".repeat(33)].map(mapped)).toEqual([false, false, false]);
		expect(parses({ idps: { a: idp({ "upstream-amr": { "": "mfa" } }) } })).toBe(false);
	});

	it("refuses an IdP with an empty type, and a key it does not know", () => {
		expect(parses({ idps: { a: { type: "" } } })).toBe(false);
		expect(parses({ unknown: 1 })).toBe(false);
	});
});
