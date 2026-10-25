import { describe, expect, it } from "vitest";
import { type Difference, differencesIn, differencesOf } from "../differences.ts";

const known = { items: new Map(), decisions: new Map() };
const registry = { libraries: ["authlib", "nimbus"], flows: ["login", "refresh"] };
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
		expect(differencesIn(JSON.stringify({ differences: [third] }), known, registry)).toEqual([
			third,
		]);
		expect(() =>
			differencesIn(
				JSON.stringify({ differences: [{ ...third, issue: "a bug", check: "" }] }),
				known,
				registry,
			),
		).toThrow(
			[
				"known differences:",
				'difference 0 (authlib login ""): names no library, flow, check or reason',
				'difference 0 (authlib login ""): names no issue URL at https',
			].join("\n"),
		);
		expect(() => differencesIn("{}", known, registry)).toThrow("no list of differences");
	});

	it("name only libraries the harness runs, so none is left out of every run unseen", () => {
		expect(() =>
			differencesIn(
				JSON.stringify({ differences: [{ ...third, library: "authllib" }] }),
				known,
				registry,
			),
		).toThrow(
			'difference 0 (authllib login "signs in with client_secret_basic"): names authllib, which the harness does not run',
		);
	});

	it("name only flows the harness has, so a misspelt or removed one is not passed over unseen", () => {
		expect(() =>
			differencesIn(JSON.stringify({ differences: [{ ...third, flow: "logn" }] }), known, registry),
		).toThrow(
			'difference 0 (authlib logn "signs in with client_secret_basic"): names the flow logn, which the harness does not have',
		);
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
