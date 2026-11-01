import type { Pkg } from "@mod/guard-imports";
import { describe, expect, it, vi } from "vitest";
import { check } from "../src/contract.ts";
import { budget, pkg } from "./workspace.ts";

// A fixture with exports has its contract surface built by the type checker, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

// Static-analysis specimens: packages written for the guard to read, never composed. Each is a sound
// workspace but for one module's misdesign, and the whole workspace's violations are checked.
const kernel = pkg(
	"@mis/kernel",
	{
		"src/contract.ts": [
			"export interface Contract<T> { readonly label: string; readonly _t?: T }",
			"export const contract = <T>(label: string): Contract<T> => ({ label });",
			"export const defineModule = (d: object, parts: (m: unknown) => unknown[]) => ({ d, parts });",
		].join("\n"),
	},
	{ exports: { ".": "./src/contract.ts" } },
	"foundation",
);
/** A module named `name` of `kind`, providing its contract by `by`, with `before` above its definition. */
const feature = (name: string, by = "() => ({})", before = "", kind = "feature") =>
	pkg(
		name,
		{
			"src/contract.ts": `import { contract } from "@mis/kernel";\nexport const offered = contract<object>("${name}");\n`,
			"src/module.ts": [
				'import { defineModule } from "@mis/kernel";',
				'import { offered } from "./contract.ts";',
				before,
				`export default defineModule({ name: "${name}", takes: [] }, (m: any) => [m.provide(offered).by(${by})]);`,
			].join("\n"),
		},
		{
			exports: { ".": "./src/contract.ts", "./module": "./src/module.ts" },
			dependencies: { "@mis/kernel": "*" },
		},
		kind,
	);
const sound: readonly Pkg[] = [
	kernel,
	feature("@mis/tokens", "() => ({ issue: () => 'a token' })"),
];
/** The rules the whole workspace raises with `misdesigned` in it. */
const raised = (misdesigned: Pkg) =>
	[...new Set(check([...sound, misdesigned], budget).map((v) => v.rule.split(" ")[0]))].sort();

describe("static-analysis specimens: misdesigns the guard stops", () => {
	it("raises nothing for the sound workspace the specimens are put in", () => {
		expect(check([...sound, feature("@mis/plain")], budget)).toEqual([]);
	});

	it("G26 stops a feature that reaches another server directly", () => {
		const reaching = feature(
			"@mis/fetches",
			'() => ({ ask: () => fetch("https://upstream.example") })',
		);
		expect(raised(reaching)).toEqual(["G26"]);
	});

	it("G13 stops a feature that reads the host's clock", () => {
		expect(raised(feature("@mis/clock", "() => ({ now: () => Date.now() })"))).toEqual(["G13"]);
	});

	it("G23 stops a feature that draws its own randomness", () => {
		expect(raised(feature("@mis/random", "() => ({ draw: () => Math.random() })"))).toEqual([
			"G23",
		]);
	});

	it("G15 stops a wiring that branches", () => {
		const deciding = feature(
			"@mis/wiring",
			"() => ({ pick: (x: number) => (x > 0 ? 1 : 2) })",
			"",
			"wiring",
		);
		expect(raised(deciding)).toEqual(["G15"]);
	});
});

describe("static-analysis specimens: misdesigns the guard does not detect", () => {
	// The boot check refuses a module that declares itself unsafe on several instances, or declares
	// nothing of them, and never reads what a module keeps: a false declaration of safety passes it, as
	// modules/foundation/kernel/src/deployment/test/deployment.test.ts shows ("boots a module keeping a
	// used id in its own process that falsely declares itself safe, and two instances take it twice").
	// Human review required; no automated detection demonstrated.
	it("guard does not detect a feature that keeps one-use state in memory", () => {
		const remembering = feature(
			"@mis/once-in-memory",
			"() => ({ use: (id: string) => (spent.has(id) ? false : (spent.add(id), true)) })",
			"const spent = new Set<string>();",
		);
		expect(raised(remembering)).toEqual([]);
	});

	// The fault scenes catch a grant while the store cannot answer only on the routes they cover, such
	// as modules/tooling/conformance-oauth/src/token-unavailable/test/token-unavailable.faults.case.ts
	// and modules/tooling/conformance-code/src/authorize-unavailable/test/authorize-unavailable.faults.case.ts.
	it("guard does not detect a feature that grants where what it waits on cannot answer", () => {
		const open = feature(
			"@mis/fail-open",
			"() => ({ allowed: (ask: () => Promise<boolean>) => ask().catch(() => true) })",
		);
		expect(raised(open)).toEqual([]);
	});

	// No scene reads a running server's log lines. Human review required; no automated detection demonstrated.
	it("guard does not detect a feature that writes a token into a log line", () => {
		const telling = feature(
			"@mis/logs-token",
			'() => ({ told: (log: { info(e: string, f: object): void }, token: string) => log.info("issued", { token }) })',
		);
		expect(raised(telling)).toEqual([]);
	});

	// Its dependencies and its shape are sound: the guard reads how code is laid out, not whose job it
	// does (CONCEPT.md, "Refuse mistakes mechanically": neither the guard nor the kernel can decide
	// whether a contract assigns responsibility well). Human review required; no automated detection
	// demonstrated.
	it("guard does not detect a feature that does another feature's job, its dependencies sound", () => {
		const duplicating = feature(
			"@mis/own-tokens",
			"() => ({ issue: (subject: string) => subject + '.self-made-token' })",
		);
		expect(raised(duplicating)).toEqual([]);
	});
});
