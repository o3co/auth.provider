import { describe, expect, it } from "vitest";
import { type Difference, differencesIn, differencesOf } from "../differences.ts";

const known = { items: new Map(), decisions: new Map() };
const registry = {
	libraries: ["authlib", "nimbus"],
	flows: ["login", "refresh", "client-credentials"],
};
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

	// A spec of the fixture's own, so no ID here reads as a real item's.
	it("take an optional behaviour by its spec's ledger, refusing one whose check names an item the section binds", () => {
		const ledgers = new Map([
			[
				"example-spec",
				{
					source: "https://example.org/example-spec.txt",
					version: "1",
					sha256: "0".repeat(64),
					rows: [
						{
							section: "3",
							ordinal: 1,
							keyword: "MUST" as const,
							to: { kind: "items" as const, ids: ["example-spec-3-i"] },
						},
					],
				},
			],
		]);
		const optional: Difference = {
			library: "nimbus",
			flow: "client-credentials",
			check: "gets a token, its assertion naming the token endpoint",
			class: "optional",
			spec: "example-spec",
			section: "3",
			reason:
				"the provider takes no token endpoint as an assertion's audience, which the spec's section 3 leaves to the client",
		};
		const withLedgers = { ...known, ledgers };
		expect(
			differencesIn(JSON.stringify({ differences: [optional] }), withLedgers, registry),
		).toEqual([optional]);
		const bound = {
			...optional,
			check: "gets a token, its assertion naming the token endpoint [example-spec-3-i]",
		};
		expect(() =>
			differencesIn(JSON.stringify({ differences: [bound] }), withLedgers, registry),
		).toThrow("its test names example-spec-3-i, which section 3's MUST names");
	});
});
