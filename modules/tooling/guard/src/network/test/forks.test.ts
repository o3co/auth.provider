import { renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Pkg } from "@mod/guard-imports";
import { describe, expect, it, vi } from "vitest";
import { budget, pkg } from "../../../test/workspace.ts";
import { check } from "../../contract.ts";

// Each case checks a package, its sources bound by the type checker, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

const starter = "src/resolver/process.ts";
const helper = "src/resolver/helper.mjs";

/** The launch form, as the starter writes it; `change` swaps one piece of it. */
const launch = (change: (text: string) => string = (t) => t) =>
	change(
		[
			'import { fork } from "node:child_process";',
			'import { join } from "node:path";',
			"export const started = (gen: number, threads: number) =>",
			'\tfork(join(import.meta.dirname, "helper.mjs"), [String(gen)], {',
			"\t\texecPath: process.execPath,",
			'\t\texecArgv: ["--max-old-space-size=16"],',
			"\t\tenv: { UV_THREADPOOL_SIZE: String(threads), LOCALDOMAIN: process.env.LOCALDOMAIN },",
			'\t\tstdio: ["ignore", "ignore", "inherit", "ipc"],',
			'\t\tserialization: "json",',
			"\t});",
			"",
		].join("\n"),
	);
const dnsOnly =
	'import { lookup } from "node:dns/promises";\nprocess.on("message", async (m) => process.send(await lookup(m.name)));\n';

/** A package declaring `outbound` and the starter's helper in `forks`, with its files as given. */
function starting(
	files: Record<string, string> = {},
	manifest: Record<string, unknown> = { forks: { [starter]: helper } },
	name = "@t/starts",
): Pkg {
	const p = pkg(
		name,
		{
			"src/contract.ts": "export const n = 1;\n",
			"src/resolver/README.md": "# resolver\n",
			[starter]: launch(),
			[helper]: dnsOnly,
			...files,
		},
		{ exports: { ".": "./src/contract.ts" }, network: "outbound", ...manifest },
		"foundation",
	);
	return { ...p, card: `# ${name}\n\n- \`network\`: \`outbound\`\n` };
}

/** What G26 says of a package, as `where detail`. */
const said = (p: Pkg) =>
	check([p], budget)
		.filter((v) => v.rule.startsWith("G26"))
		.map((v) => `${v.where.replace(`${p.name}/`, "")} ${v.detail}`);

describe("G26: the one starter forks declares, starting its helper as written", () => {
	it("takes the launch form and a helper that resolves names alone", () => {
		expect(said(starting())).toEqual([]);
	});

	it("refuses a process started by a file forks does not name, or in a package not declaring outbound", () => {
		expect(said(starting({}, { forks: {} }))).toEqual([
			`${starter} node:child_process (forks does not name it)`,
		]);
		const plain = { ...starting(), manifest: { ...starting().manifest, network: "serves-http" } };
		expect(said(plain)).toContainEqual(
			`${starter} node:child_process (forks needs the word outbound)`,
		);
	});

	it("refuses another name or form of node:child_process, and fork used otherwise than in one call", () => {
		const refused = (change: (t: string) => string) =>
			said(starting({ [starter]: launch(change) }, undefined, `@t/s${Math.random()}`));
		const imported = "imports from node:child_process fork by its name alone";
		expect(refused((t) => t.replace("{ fork }", "{ fork, spawn }"))).toEqual([
			`${starter} node:child_process (${imported})`,
		]);
		expect(
			refused((t) =>
				t.replace("import { fork }", "import * as cp").replace("\tfork(", "\tcp.fork("),
			),
		).toEqual([`${starter} node:child_process (${imported})`]);
		expect(refused((t) => `${t}export const again = fork;\n`)).toEqual([
			`${starter} node:child_process (uses fork in one call alone)`,
		]);
	});

	it("refuses a helper not named as join(import.meta.dirname, its file), or not a plain file beside the starter", () => {
		const refused = (files: Record<string, string>, manifest?: Record<string, unknown>) =>
			said(starting(files, manifest, `@t/h${Math.random()}`));
		const named = 'names the helper as join(import.meta.dirname, "helper.mjs")';
		expect(refused({ [starter]: launch((t) => t.replace('"helper.mjs"', '"other.mjs"')) })).toEqual(
			[`${starter} node:child_process (${named})`],
		);
		expect(
			refused({
				[starter]: launch((t) =>
					t.replace('join(import.meta.dirname, "helper.mjs")', "process.argv[2]"),
				),
			}),
		).toEqual([`${starter} node:child_process (${named})`]);
		expect(
			refused({
				[starter]: launch((t) =>
					t.replace(
						'import { join } from "node:path";',
						"const join = (...p: string[]) => p.join('/');",
					),
				),
			}),
		).toEqual([`${starter} node:child_process (${named})`]);
		// Named elsewhere and not there: refused at the starter, and the helper reported unread.
		expect(refused({}, { forks: { [starter]: "src/other/helper.mjs" } })).toEqual([
			`${starter} node:child_process (forks names a helper beside it, a plain .mjs file)`,
			"src/other/helper.mjs (forks names it, but it is no plain .mjs file)",
		]);
	});

	it("refuses a symlink for the helper", () => {
		const p = starting({}, undefined, "@t/linked");
		const target = join(p.dir, "src/resolver/real.mjs");
		writeFileSync(target, dnsOnly);
		const linked = join(p.dir, helper);
		rmSync(linked);
		symlinkSync(target, linked);
		expect(said(p)).toContainEqual(
			`${starter} node:child_process (forks names a helper beside it, a plain .mjs file)`,
		);
	});

	it("refuses options other than the launch form", () => {
		const refused = (change: (t: string) => string) =>
			said(starting({ [starter]: launch(change) }, undefined, `@t/o${Math.random()}`));
		const form = "starts it in the launch form";
		for (const change of [
			(t: string) => t.replace("process.execPath", '"/usr/bin/node"'),
			(t: string) => t.replace('"--max-old-space-size=16"', '"--require=./x.js"'),
			(t: string) => t.replace('"--max-old-space-size=16"', '"--inspect"'),
			(t: string) => t.replace('["--max-old-space-size=16"]', "[]"),
			(t: string) =>
				t.replace(
					'["--max-old-space-size=16"]',
					'["--max-old-space-size=16", "--max-old-space-size=4096"]',
				),
			(t: string) =>
				t.replace("LOCALDOMAIN: process.env.LOCALDOMAIN", "NODE_OPTIONS: process.env.NODE_OPTIONS"),
			(t: string) => t.replace("env: {", "env: { ...process.env,"),
			(t: string) => t.replace('"inherit", "ipc"', '"inherit", "pipe", "ipc"'),
			(t: string) => t.replace('serialization: "json",', 'serialization: "advanced",'),
			(t: string) => t.replace('serialization: "json",', 'serialization: "json",\n\t\tcwd: "/",'),
		]) {
			expect(refused(change)).toEqual([`${starter} node:child_process (${form})`]);
		}
	});

	it("refuses a starter loading node:child_process again, or shadowing fork, join or process", () => {
		const refused = (change: (t: string) => string) =>
			said(starting({ [starter]: launch(change) }, undefined, `@t/b${Math.random()}`));
		const again = `${starter} node:child_process (loads node:child_process by the import alone)`;
		expect(
			refused(
				(t) =>
					`${t}export const more = async () => (await import("node:child_process")).exec("id");\n`,
			),
		).toContainEqual(again);
		expect(
			refused((t) => `${t}export const twice = () => require("node:child_process");\n`),
		).toContainEqual(again);
		const head = "export const started = (gen: number, threads: number) =>";
		expect(
			refused((t) =>
				t.replace(
					head,
					"export const started = (gen: number, threads: number, join = (...p: string[]) => p[1]) =>",
				),
			),
		).toEqual([
			`${starter} node:child_process (names the helper as join(import.meta.dirname, "helper.mjs"))`,
		]);
		expect(
			refused((t) => t.replace(head, `const process = { execPath: "/bin/sh", env: {} };\n${head}`)),
		).toEqual([`${starter} node:child_process (starts it in the launch form)`]);
		expect(
			refused((t) =>
				t.replace(
					head,
					"export const started = (gen: number, threads: number, fork = (...a: unknown[]) => a) =>",
				),
			),
		).toEqual([`${starter} node:child_process (uses fork in one call alone)`]);
		// Read again under another name: a shorthand property, an export, an export's alias.
		const once = `${starter} node:child_process (uses fork in one call alone)`;
		expect(
			refused(
				(t) =>
					`${t}const escaped = { fork };\nexport const run = () => escaped.fork("/tmp/arbitrary.mjs");\n`,
			),
		).toEqual([once]);
		expect(refused((t) => `${t}export { fork };\n`)).toEqual([once]);
		expect(refused((t) => `${t}export { fork as start };\n`)).toEqual([once]);
	});

	it("refuses forks naming more than one starter, or a helper that is no .mjs file", () => {
		const two = { forks: { [starter]: helper, "src/resolver/other.ts": "src/resolver/other.mjs" } };
		expect(
			said(
				starting(
					{ "src/resolver/other.ts": launch(), "src/resolver/other.mjs": dnsOnly },
					two,
					"@t/two",
				),
			),
		).toContainEqual("@t/two forks names one starter and its helper");
		const cjs = { forks: { [starter]: "src/resolver/helper.cjs" } };
		const found = said(
			starting(
				{
					[starter]: launch((t) => t.replace('"helper.mjs"', '"helper.cjs"')),
					"src/resolver/helper.cjs": "require('node:https');\n",
				},
				cjs,
				"@t/cjs",
			),
		);
		expect(found).toContainEqual(
			`${starter} node:child_process (forks names a helper beside it, a plain .mjs file)`,
		);
	});

	it("refuses a helper importing anything but node:dns/promises' lookup, or reaching the network otherwise", () => {
		const refused = (text: string) =>
			said(starting({ [helper]: text }, undefined, `@t/d${Math.random()}`));
		const alone = "imports node:dns/promises' lookup alone";
		expect(
			refused(
				'import { lookup } from "node:dns/promises";\nimport { readFileSync } from "node:fs";\n',
			),
		).toEqual([`${helper} (${alone})`]);
		expect(refused('import { connect } from "node:net";\n')).toEqual([`${helper} (${alone})`]);
		expect(refused(`${dnsOnly}fetch("https://x.example");\n`)).toEqual([
			`${helper} fetch`,
			`${helper} (${alone})`,
		]);
		for (const loading of [
			'import("node:fs");\n',
			'import("./other.mjs");\n',
			'export * from "./other.mjs";\n',
			'export { lookup as l } from "node:dns/promises";\n',
			'require("node:fs");\n',
			'import "./more.mjs";\n',
		]) {
			expect(refused(`${dnsOnly}${loading}`), loading).toContainEqual(`${helper} (${alone})`);
		}
		// Covered by the word outbound, but not a helper's to reach.
		expect(refused(`${dnsOnly}const m = await import("node:https");\n`)).toEqual([
			`${helper} (${alone})`,
		]);
	});
});

describe("G26: what else a starter and its helpers may hold", () => {
	const refused = (change: (t: string) => string) =>
		said(starting({ [starter]: launch(change) }, undefined, `@t/c${Math.random()}`));

	it("refuses child_process reached another way, by its bare name or a re-export", () => {
		const imported = `${starter} node:child_process (imports from node:child_process fork by its name alone)`;
		expect(
			refused((t) => `import { spawn } from "child_process";\n${t}export const s = spawn;\n`),
		).toContainEqual(imported);
		expect(refused((t) => `${t}export { exec } from "node:child_process";\n`)).toContainEqual(
			imported,
		);
		expect(refused((t) => `${t}export * from "child_process";\n`)).toContainEqual(imported);
		expect(
			refused((t) => `${t}export const later = () => import("child_process");\n`),
		).toContainEqual(
			`${starter} node:child_process (loads node:child_process by the import alone)`,
		);
	});

	it("takes a type read of fork, a type-only export, and a dynamic import of another module", () => {
		expect(refused((t) => `${t}export type Started = ReturnType<typeof fork>;\n`)).toEqual([]);
		expect(refused((t) => `${t}export type { fork };\n`)).toEqual([]);
		expect(
			refused((t) => `${t}export const os = async () => (await import("node:os")).cpus();\n`),
		).toEqual([]);
	});

	it("still refuses a module loaded by a name known at run time alone", () => {
		expect(
			refused((t) => `${t}export const any = (name: string) => import(name);\n`),
		).toContainEqual(
			`${starter} node:child_process (loads node:child_process by the import alone)`,
		);
	});

	it("reports a helper that is no plain .mjs file without reading it, never stopping", () => {
		for (const named of ["src/resolver/README.md", "src/resolver", "src/resolver/missing.mjs"]) {
			const p = starting({}, { forks: { [starter]: named } }, `@t/n${Math.random()}`);
			let found: string[] = [];
			expect(() => {
				found = said(p);
			}, named).not.toThrow();
			expect(found, named).toContainEqual(
				`${named} (forks names it, but it is no plain .mjs file)`,
			);
		}
	});

	it("counts what a helper checked apart reaches toward the package's word", () => {
		// The helper is the package's published test suite, so the scan of shipped sources passes it by.
		const p = starting(
			{},
			{
				forks: { [starter]: helper },
				exports: { ".": "./src/contract.ts", "./testing": `./${helper}` },
			},
			"@t/apart",
		);
		expect(said(p)).not.toContainEqual("@t/apart outbound reaches nothing here");
	});
});

describe("G26: a starter as it is shipped", () => {
	const refused = (change: (t: string) => string) =>
		said(starting({ [starter]: launch(change) }, undefined, `@t/d${Math.random()}`));

	it("refuses require called through parentheses, and counts a read of fork in a class's extends", () => {
		expect(
			refused(
				(t) =>
					`import { createRequire } from "node:module";\n${t}const require = createRequire(import.meta.url);\nexport const x = () => (require)("node:child_process");\n`,
			),
		).toContainEqual(
			`${starter} node:child_process (loads node:child_process by the import alone)`,
		);
		expect(
			refused(
				(t) =>
					`${t}const capture = (f: unknown) => f;\nexport class C extends (capture(fork), Object) {}\n`,
			),
		).toEqual([`${starter} node:child_process (uses fork in one call alone)`]);
	});

	it("refuses a starter that is a link, whose helper is the one beside the file it links to", () => {
		const p = starting({}, undefined, "@t/linked-starter");
		const real = join(p.dir, "src/resolver/real.ts");
		renameSync(join(p.dir, starter), real);
		symlinkSync(real, join(p.dir, starter));
		expect(said(p)).toContainEqual(`${starter} node:child_process (is a plain file, never a link)`);
	});

	it("refuses forks naming a starter that is no shipped source", () => {
		const p = starting({}, { forks: { "src/missing.ts": helper } }, "@t/no-starter");
		expect(said(p)).toContainEqual("src/missing.ts (forks names it, but it is no shipped source)");
	});
});

describe("G26: a declared starter, checked whatever it reaches", () => {
	it("refuses a starter that only re-exports fork, or reaches node:child_process not at all", () => {
		const imported = `${starter} node:child_process (imports from node:child_process fork by its name alone)`;
		const reexported = said(
			starting(
				{ [starter]: 'export { fork } from "node:child_process";\n' },
				undefined,
				"@t/re-only",
			),
		);
		expect(reexported).toContainEqual(imported);
		const none = said(starting({ [starter]: "export const n = 1;\n" }, undefined, "@t/no-fork"));
		expect(none).toContainEqual(imported);
	});
});
