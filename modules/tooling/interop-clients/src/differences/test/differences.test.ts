import { describe, expect, it } from "vitest";
import { type Difference, differencesIn, differencesOf } from "../differences.ts";

const known = { items: new Map(), decisions: new Map() };
const third: Difference = {
	library: "authlib",
	flow: "login",
	check: "signs in with client_secret_basic",
	class: "third-party",
	issue: "https://github.com/authlib/authlib/issues/1",
	reason: "the library does not form-encode the secret before Basic",
};

describe("the known differences", () => {
	it("are read as written, each held to the exceptions' rules and written narrowly", () => {
		expect(differencesIn(JSON.stringify({ differences: [third] }), known)).toEqual([third]);
		expect(() =>
			differencesIn(
				JSON.stringify({ differences: [{ ...third, issue: "a bug", check: "" }] }),
				known,
			),
		).toThrow(
			[
				"known differences:",
				'difference 0 (authlib login ""): names no library, flow, check or reason',
				'difference 0 (authlib login ""): names no issue URL at https',
			].join("\n"),
		);
		expect(() => differencesIn("{}", known)).toThrow("no list of differences");
	});

	it("excuse only the library's check they name, and tell the ones no check met", () => {
		const of = differencesOf([third], "authlib");
		expect(of.excusing("login", "signs in with client_secret_post")).toBeUndefined();
		expect(of.unmet()).toEqual([third]);
		expect(of.excusing("login", third.check)).toBe(third);
		expect(of.unmet()).toEqual([]);
		expect(differencesOf([third], "nimbus").unmet()).toEqual([]);
	});
});
