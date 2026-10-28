import type { Pkg } from "@mod/guard-imports";
import { describe, expect, it, vi } from "vitest";
import { check } from "../src/contract.ts";
import { budget, pkg } from "./workspace.ts";

// A fixture with exports has its contract surface built by the type checker, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

// Each case is one misdesign of a module whose shape is otherwise sound: the rule that stops it, or
// none, where a review, a boot check or a conformance scene is the gate. docs/gates.md names them.
const kernel = pkg(
	"@mis/kernel",
	{
		"src/contract.ts":
			"export const defineModule = (d: object, f: () => unknown[]) => ({ d, f });\n",
	},
	{ exports: { ".": "./src/contract.ts" } },
	"foundation",
);
/** A feature whose module is `module`, depending on the kernel alone. */
const feature = (name: string, module: string, kind = "feature") =>
	pkg(
		name,
		{ "src/contract.ts": "export const used = 1;\n", "src/module.ts": module },
		{
			exports: { ".": "./src/contract.ts", "./module": "./src/module.ts" },
			dependencies: { "@mis/kernel": "*" },
		},
		kind,
	);
/** Every rule the whole check raises on a module's misdesign, among a workspace otherwise sound. */
const raised = (misdesigned: Pkg) =>
	[
		...new Set(
			check([kernel, misdesigned], budget)
				.filter((v) => v.where.startsWith(misdesigned.name))
				.map((v) => v.rule.split(" ")[0]),
		),
	].sort();
const module = (body: string) =>
	`import { defineModule } from "@mis/kernel";\nexport default defineModule({ name: "m" }, () => [${body}]);\n`;

describe("misdesigns the guard stops", () => {
	it("G26 stops a feature reaching another server itself, past outbound's policy", () => {
		const reaching = feature("@mis/fetches", module('() => fetch("https://upstream.example")'));
		expect(raised(reaching)).toEqual(["G26"]);
	});

	it("G13 stops a feature reading the host's clock, past the kernel's", () => {
		expect(raised(feature("@mis/clock", module("() => Date.now()")))).toEqual(["G13"]);
	});

	it("G23 stops a feature drawing its own randomness, past the kernel's", () => {
		expect(raised(feature("@mis/random", module("() => Math.random()")))).toEqual(["G23"]);
	});

	it("G15 stops a wiring that decides, as a feature would", () => {
		const deciding = feature("@mis/wiring", module("(x: number) => (x > 0 ? 1 : 2)"), "wiring");
		expect(raised(deciding)).toEqual(["G15"]);
	});
});

// The guard reads how code is laid out, never what it means: each misdesign below keeps every rule.
// A review stops it, and a conformance scene where docs/gates.md names one; once the guard stops it,
// turn its test over.
describe("misdesigns the guard passes, a review's to stop", () => {
	it("passes a feature that keeps what is used once in its own process, though a second instance would use it again: a review's to stop; turn this test over once the guard stops it", () => {
		const remembering = feature(
			"@mis/once-in-memory",
			`const spent = new Set<string>();\n${module("(id: string) => (spent.has(id) ? false : (spent.add(id), true))")}`,
		);
		expect(raised(remembering)).toEqual([]);
	});

	it("passes a feature that grants where what it waits on cannot answer: a review's to stop; turn this test over once the guard stops it", () => {
		const open = feature(
			"@mis/fail-open",
			module("async (ask: () => Promise<boolean>) => ask().catch(() => true)"),
		);
		expect(raised(open)).toEqual([]);
	});

	it("passes a feature that writes a token into a log line: a review's to stop; turn this test over once the guard stops it", () => {
		const telling = feature(
			"@mis/logs-token",
			module(
				'(log: { info(e: string, f: object): void }, token: string) => log.info("issued", { token })',
			),
		);
		expect(raised(telling)).toEqual([]);
	});
});
