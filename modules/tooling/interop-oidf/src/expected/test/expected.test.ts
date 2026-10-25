import type { Decision, Item } from "@mod/spec-checklist";
import { describe, expect, it } from "vitest";
import { type Expected, expectedProblems, suiteEntries } from "../expected.ts";

const item = (id: string, strength: Item["strength"], mark?: Item["mark"]): Item =>
	({ id, strength, text: "", ...(mark ? { mark } : {}) }) as Item;
const known = {
	items: new Map<string, Item>([
		[
			"a-must-item",
			item("a-must-item", "MUST", { kind: "noncompliant", issue: "#1" } as Item["mark"]),
		],
		["a-should-item", item("a-should-item", "SHOULD")],
	]),
	decisions: new Map<string, Decision>(),
};

/** An entry as written, with any field changed or left out (`undefined`). */
const failure = (fields: Record<string, unknown> = {}): Expected =>
	({
		"test-name": "oidcc-ensure-redirect-uri-in-authorization-request",
		variant: { server_metadata: "discovery", client_registration: "static_client" },
		"configuration-filename": "basic.json",
		"current-block": "Verify authorization endpoint response",
		condition: "CheckForAuthorizationEndpointErrorInQueryParameters",
		"expected-result": "failure",
		class: "adaptation",
		adaptation: "pkce",
		...fields,
	}) as Expected;

describe("an expected result the harness gives the suite", () => {
	it("is taken when it names its test exactly and its class holds", () => {
		expect(expectedProblems([failure()], "failure", known)).toEqual([]);
		expect(
			expectedProblems(
				[failure({ class: "noncompliant", item: "a-must-item", adaptation: undefined })],
				"failure",
				known,
			),
		).toEqual([]);
	});

	it("is refused with a wildcard in the test's name or configuration file", () => {
		const wild = [
			failure({ "test-name": "oidcc-*" }),
			failure({ "configuration-filename": "basic?.json" }),
			failure({ "test-name": "oidcc-[ab]" }),
		];
		expect(expectedProblems(wild, "failure", known)).toEqual([
			expect.stringContaining("test-name"),
			expect.stringContaining("configuration-filename"),
			expect.stringContaining("test-name"),
		]);
	});

	it("is refused with every variant or no variant", () => {
		const problems = expectedProblems(
			[failure({ variant: "*" as never }), failure({ variant: undefined as never })],
			"failure",
			known,
		);
		expect(problems).toHaveLength(2);
		for (const p of problems) expect(p).toContain("variant");
	});

	it("is refused without its block and condition, as a failure is", () => {
		const problems = expectedProblems(
			[failure({ "current-block": undefined as never, condition: "" })],
			"failure",
			known,
		);
		expect(problems).toEqual([
			expect.stringContaining("current-block"),
			expect.stringContaining("condition"),
		]);
	});

	it("needs no block or condition as a skip", () => {
		const skip = {
			...failure(),
			"current-block": undefined,
			condition: undefined,
			"expected-result": undefined,
		};
		expect(expectedProblems([skip as never], "skip", known)).toEqual([]);
	});

	it("is refused where its class does not hold, as the checklist judges it", () => {
		const problems = expectedProblems(
			[
				failure({ "test-name": "t1", class: undefined as never, adaptation: undefined }),
				failure({
					"test-name": "t2",
					class: "deviates",
					item: "a-should-item",
					adaptation: undefined,
				}),
				failure({
					"test-name": "t3",
					class: "third-party",
					adaptation: undefined,
					issue: "http://x",
				}),
			],
			"failure",
			known,
		);
		expect(problems).toEqual([
			expect.stringContaining("class"),
			expect.stringContaining("not marked deviates"),
			expect.stringContaining("issue URL"),
		]);
	});

	it("is refused twice written, or beside another class for the same test", () => {
		const other = failure({
			condition: "Another",
			class: "third-party",
			adaptation: undefined,
			issue: "https://x",
		});
		expect(expectedProblems([failure(), failure()], "failure", known)).toEqual([
			expect.stringContaining("twice"),
		]);
		expect(expectedProblems([failure(), other], "failure", known)).toEqual([
			expect.stringContaining("one class"),
		]);
	});

	it("goes to the suite with the suite's own fields alone", () => {
		expect(suiteEntries([failure()])).toEqual([
			{
				"test-name": "oidcc-ensure-redirect-uri-in-authorization-request",
				variant: { server_metadata: "discovery", client_registration: "static_client" },
				"configuration-filename": "basic.json",
				"current-block": "Verify authorization endpoint response",
				condition: "CheckForAuthorizationEndpointErrorInQueryParameters",
				"expected-result": "failure",
			},
		]);
	});

	it("takes a failure outside any block, as the suite logs some, by its empty block", () => {
		expect(expectedProblems([failure({ "current-block": "" })], "failure", known)).toEqual([]);
	});

	it("takes an optional result where its spec and section are named, as the checklist judges it", () => {
		const optional = failure({
			class: "optional",
			spec: "oidc-core",
			section: "5.4",
			adaptation: undefined,
		});
		const withLedgers = { ...known, ledgers: new Map([["oidc-core", { rows: [] } as never]]) };
		expect(expectedProblems([optional], "failure", withLedgers)).toEqual([]);
		expect(
			expectedProblems(
				[failure({ class: "optional", spec: "oidc-core", adaptation: undefined })],
				"failure",
				withLedgers,
			),
		).toEqual([expect.stringContaining("section")]);
	});
});
