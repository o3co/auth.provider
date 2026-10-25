import { describe, expect, it } from "vitest";
import { conditionsSetting, meets } from "../conditions.ts";

const read = (written: unknown) => conditionsSetting.safeParse(written);
const held = (written: unknown) => {
	const parsed = read(written);
	if (!parsed.success) throw new Error("not read");
	return parsed.data;
};

describe("conditions as written", () => {
	it("takes a subject prefix and claims, each value one or a list of strings, numbers or booleans", () => {
		expect(read({ "subject-prefix": "repo:acme/" }).success).toBe(true);
		expect(
			read({ claims: { environment: "prod", runs: 3, ci: true, ref: ["a", "b"] } }).success,
		).toBe(true);
		expect(read({ "subject-prefix": "repo:acme/", claims: { environment: "prod" } }).success).toBe(
			true,
		);
	});

	it("refuses conditions that hold no predicate, so none passes for one", () => {
		for (const empty of [{}, { claims: {} }, { "subject-prefix": "" }, { claims: { a: [] } }]) {
			expect(read(empty).success, JSON.stringify(empty)).toBe(false);
		}
	});

	it("refuses a field it does not know, a value of another kind, and a claim the grant's policy decides", () => {
		expect(read({ subjects: "x" }).success).toBe(false);
		expect(read({ claims: { a: { b: 1 } } }).success).toBe(false);
		expect(read({ claims: { a: null } }).success).toBe(false);
		expect(read({ claims: { a: [["x"]] } }).success).toBe(false);
		for (const name of ["iss", "aud", "exp", "nbf", "iat", "jti"]) {
			expect(read({ claims: { [name]: "x" } }).success, name).toBe(false);
		}
		expect(read({ claims: { sub: "x" } }).success).toBe(true);
	});

	it("takes a prefix of 1 to 255 printable ASCII characters", () => {
		expect(read({ "subject-prefix": "a".repeat(255) }).success).toBe(true);
		for (const bad of ["a".repeat(256), "é", "a b", "a\n"]) {
			expect(read({ "subject-prefix": bad }).success, JSON.stringify(bad)).toBe(false);
		}
	});
});

describe("whether verified claims meet them", () => {
	it("holds the sub to the prefix as written: case, spaces and forms apart", () => {
		const c = held({ "subject-prefix": "repo:acme/" });
		expect(meets(c, { sub: "repo:acme/app:ref:main" })).toBe(true);
		for (const sub of ["repo:ACME/app", " repo:acme/app", "repo:acm/app", "repo:acme", 5]) {
			expect(meets(c, { sub }), JSON.stringify(sub)).toBe(false);
		}
		// A value is compared as written: forms Unicode would normalize alike are apart.
		const team = held({ claims: { team: "\u00e9quipe" } });
		expect(meets(team, { team: "\u00e9quipe" })).toBe(true);
		expect(meets(team, { team: "e\u0301quipe" })).toBe(false);
	});

	it("holds each claim to its value, or one of its values, by kind as well", () => {
		const c = held({ claims: { environment: ["prod", "staging"], runs: 1, ci: true } });
		expect(meets(c, { environment: "prod", runs: 1, ci: true })).toBe(true);
		expect(meets(c, { environment: "staging", runs: 1, ci: true })).toBe(true);
		expect(meets(c, { environment: "dev", runs: 1, ci: true })).toBe(false);
		expect(meets(c, { environment: "prod", runs: "1", ci: true })).toBe(false);
		expect(meets(c, { environment: "prod", runs: 1, ci: "true" })).toBe(false);
		expect(meets(c, { runs: 1, ci: true })).toBe(false);
		expect(meets(c, { environment: ["prod"], runs: 1, ci: true })).toBe(false);
		expect(meets(c, { environment: { prod: true }, runs: 1, ci: true })).toBe(false);
	});

	it("holds every predicate together", () => {
		const c = held({ "subject-prefix": "repo:acme/", claims: { environment: "prod" } });
		expect(meets(c, { sub: "repo:acme/app", environment: "prod" })).toBe(true);
		expect(meets(c, { sub: "repo:other/app", environment: "prod" })).toBe(false);
		expect(meets(c, { sub: "repo:acme/app", environment: "dev" })).toBe(false);
	});

	it("reads a claim only as the claims' own, never one of an object's", () => {
		for (const name of ["constructor", "toString", "hasOwnProperty"]) {
			const c = held({ claims: { [name]: "x" } });
			expect(meets(c, {}), name).toBe(false);
		}
		// One named `__proto__` is read as naming no claim, and refused.
		expect(read({ claims: { ["__proto__"]: "x" } }).success).toBe(false);
		expect(meets(held({ claims: { toString: "x" } }), { toString: "x" })).toBe(true);
	});
});
