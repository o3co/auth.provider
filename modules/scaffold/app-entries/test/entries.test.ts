import { spawn, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { type Declaring, entriesOf } from "../src/contract.ts";
import { configFiles, kernel, mainSource } from "../src/start.ts";

/** Stand-ins for the kernel (with config-files' `loadConfig`) and mfa-witnessing, as packages the written script imports. */
const fakes: Record<string, Record<string, string>> = {
	"fake-kernel": {
		"index.js": `
const mark = Symbol.for("@mod/kernel.boot-refused");
export class BootRefused extends Error {
	constructor(refusals) { super("refused"); this.refusals = refusals; this[mark] = true; }
	static is(error) { return typeof error === "object" && error !== null && error[mark] === true; }
}
export const isUnavailable = (error) => error?.name === "Unavailable";
export const loadConfig = async () => ({});
// The variables 0.17 read that are set: here, any named LEGACY_*.
export const unreadLegacyVariables = async ({ env }) => Object.keys(env).filter((name) => name.startsWith("LEGACY_")).sort();
export const legacyVariablesWarning = (names) => (names.length === 0 ? undefined : \`\${names.length} named: \${names.join(", ")}\`);
// config-files' one check, as far as the entry asks: refusing under refuse, else the warning.
export const legacyVariablesCheck = async (source) => {
	const names = await unreadLegacyVariables(source);
	if (source.env.APP_LEGACY_VARIABLES === "refuse" && names.length > 0)
		throw new BootRefused([{ where: "config-files", reason: names.join(", ") }]);
	return legacyVariablesWarning(names);
};
export async function assemble({ runtime }) {
	// A refusal thrown by a second copy of the kernel: its own class, the same mark.
	if (process.env.REFUSE) throw new (await import("fake-kernel-copy")).BootRefused([{ where: "a.b", reason: "why" }]);
	// A boot that fails as no refusal, its message holding a subject and a secret.
	if (process.env.BOOT_FAILS) throw new Error("secret of alice at boot");
	// A refusal marked as the kernel's, its refusals of no shape the script can count.
	if (process.env.REFUSAL_MISSHAPED) throw Object.assign(new Error("refused"), { [mark]: true, refusals: { length: "secret of alice" } });
	// Marked alike, its refusals, or their count, throwing as they are read.
	if (process.env.REFUSALS_THROW) throw Object.defineProperty(Object.assign(new Error("refused"), { [mark]: true }), "refusals", { get() { throw new Error("secret of alice refusals"); } });
	if (process.env.LENGTH_THROWS) throw Object.assign(new Error("refused"), { [mark]: true, refusals: { get length() { throw new Error("secret of alice length"); } } });
	// Many refusals, each long, so their lines fill a pipe read slowly.
	if (process.env.REFUSE_MANY) throw new BootRefused(Array.from({ length: Number(process.env.REFUSE_MANY) }, (_, i) => ({ where: \`at.\${i}\`, reason: "r".repeat(100) })));
	// Without the script's own runtime, the composed sink would write this line.
	(runtime?.log ?? { warn: (event) => process.stdout.write(\`LOG \${event}\\n\`) }).warn("fake.assembled");
	const { backfill, candidates, tool } = await import("fake-witnessing");
	const holders = Array.from({ length: Number(process.env.HOLDERS ?? 1) }, (_, i) => \`holder-\${i}-\${"h".repeat(100)} resealed 0 left 0\`);
	const resealer = { run: async () => ({ lines: [...holders, "previous keys may be retired"], code: 0 }) };
	const asked = { resetCandidates: candidates, resealRun: resealer, toolRun: tool, lines: tool, tell: tool };
	// Where a test signals the app: kept alive once started, each stop told and slow.
	const signalled = process.env.SIGNALLED !== undefined;
	let alive;
	const start = async () => {
		if (!signalled) return;
		alive = setInterval(() => {}, 60000);
		process.stdout.write("started\\n");
	};
	const stop = async () => {
		if (!signalled) return;
		process.stdout.write("stopping\\n");
		await new Promise((resolve) => setTimeout(resolve, 300));
		clearInterval(alive);
		process.stdout.write("stopped\\n");
	};
	return { get: (what) => asked[what] ?? backfill, start, stop };
}`,
	},
	"fake-kernel-copy": {
		"index.js": `
const mark = Symbol.for("@mod/kernel.boot-refused");
export class BootRefused extends Error {
	constructor(refusals) { super("refused"); this.refusals = refusals; this[mark] = true; }
}`,
	},
	"fake-witnessing": {
		"index.js": `
import { appendFileSync } from "node:fs";
export const witnessBackfill = "witnessBackfill";
export const passkeyBackfill = "passkeyBackfill";
export const resetCandidates = "resetCandidates";
export const resealRun = "resealRun";
export const toolRun = "toolRun";
// Contracts named as the scripts' own names are: each script takes its contract under a name of its own.
export const lines = "lines";
export const end = "end";
export const tell = "tell";
/** A tool's call: its answer as the test asks for it, each holding what the script must never tell. */
export const tool = {
	run: async (args) => {
		if (process.env.TOOL_THROWS) throw new Error("secret of alice tool");
		if (process.env.TOOL_CODE !== undefined) return { lines: ["told"], code: JSON.parse(process.env.TOOL_CODE) };
		if (process.env.TOOL_MISSHAPED) return { lines: "secret of alice", code: 0 };
		if (process.env.TOOL_ANSWER !== undefined) return JSON.parse(process.env.TOOL_ANSWER);
		if (process.env.TOOL_SILENT) return { lines: [], code: 0 };
		return { lines: [\`args \${JSON.stringify(args)}\`, "done"], code: 0 };
	},
	check: async (subject) => {
		appendFileSync(process.env.SEEN, \`\${JSON.stringify(subject)}\\n\`);
		return subject.startsWith("flagged") ? 1 : 0;
	},
};
export const candidates = {
	unclaimed: async (subject) => {
		appendFileSync(process.env.SEEN, \`\${JSON.stringify(subject)}\\n\`);
		if (subject === "down") throw Object.assign(new Error("down for alice"), { name: "Unavailable" });
		if (subject === "boom") throw new Error("secret of alice");
		return subject.startsWith("claimless") ? 2 : 0;
	},
};
export const backfill = {
	settle: async (subject) => {
		appendFileSync(process.env.SEEN, \`\${JSON.stringify(subject)}\\n\`);
		if (subject === "down") throw Object.assign(new Error("down for alice"), { name: "Unavailable" });
		if (subject === "boom") throw new Error("secret of alice");
		if (subject === "late") setImmediate(() => { throw new Error("late secret of alice"); });
		if (subject === "claimless") return "unclaimed";
		if (subject === "registering") return "pending";
		if (subject === "odd") return "a word of a later release";
		return "marked";
	},
};`,
		// Read as the app's composed module is: a dependency that throws, warns, writes, ends a stream or rejects
		// while it is read, or whose exit handler throws, each holding what the script must never tell.
		"module.js": `
if (process.env.IMPORT_THROWS) throw new Error("secret of alice at import");
if (process.env.WARNS) process.emitWarning("secret of alice warning");
if (process.env.CONSOLE) {
	console.error("secret of alice console error");
	console.log("secret of alice console log");
	process.stderr.write("secret of alice stderr\\n");
	await new Promise((resolve) => process.stdout.write("secret of alice awaited\\n", resolve));
}
if (process.env.ENDS) {
	process.stderr.end("secret of alice stderr end\\n");
	await new Promise((resolve) => process.stdout.end("secret of alice stdout end\\n", resolve));
}
if (process.env.EXIT_THROWS) process.on("exit", () => { throw new Error("secret of alice at exit"); });
if (process.env.REJECTS) Promise.reject(new Error("secret of alice rejected"));
export default {};`,
	},
};

/** What the packages the fakes stand for declare of the app's entries, as their manifests do. */
const declaredByFakes: readonly Declaring[] = [
	{
		name: "@mod/seal",
		appEntries: [{ script: "reseal", shape: "call", contract: "resealRun", member: "run" }],
	},
	{
		name: "@mod/mfa-witnessing",
		appEntries: [
			{
				script: "witness-backfill",
				shape: "settle-subjects",
				contract: "witnessBackfill",
				member: "settle",
				answers: ["marked", "held", "none", "unclaimed", "inconsistent"],
			},
		],
	},
	{
		name: "@mod/passkey-witnessing",
		appEntries: [
			{
				script: "passkey-backfill",
				shape: "settle-subjects",
				contract: "passkeyBackfill",
				member: "settle",
				answers: ["marked", "held", "none", "pending", "inconsistent"],
			},
		],
	},
	{
		name: "@mod/mfa-reset",
		appEntries: [
			{
				script: "unclaimed-factors",
				shape: "name-subjects",
				contract: "resetCandidates",
				member: "unclaimed",
			},
		],
	},
];

/** The entry `runs` calls for, written over the fakes; a run of it on an input. */
async function script(
	runs = "@mod/mfa-witnessing",
	file = "src/witness-backfill.ts",
	declaring: readonly Declaring[] = declaredByFakes,
) {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	for (const [name, files] of Object.entries(fakes)) {
		const dir = join(target, "node_modules", name);
		await mkdir(dir, { recursive: true });
		const exports = { ".": "./index.js", "./module": "./module.js" };
		await writeFile(join(dir, "package.json"), JSON.stringify({ name, type: "module", exports }));
		for (const [file, text] of Object.entries(files)) await writeFile(join(dir, file), text);
	}
	const importOf = (name: string) =>
		name === kernel || name === configFiles ? "fake-kernel" : "fake-witnessing";
	const { files } = await entriesOf(
		[runs],
		importOf,
		(path) => `node ${path}`,
		undefined,
		declaring,
	);
	await mkdir(join(target, "src"));
	// The app's own entry, as `start` runs it, beside the one asked for.
	await writeFile(join(target, "src", "main.ts"), await mainSource([], importOf));
	if (files[file] !== undefined) await writeFile(join(target, file), files[file]);
	/** A run whose standard output is read only after a while, as a slow pipe reads it. */
	const slowly = (
		input: string,
		more: Record<string, string> = {},
		held: "stdout" | "stderr" = "stdout",
	) =>
		new Promise<{ stdout: string; stderr: string; status: number | null }>((resolve) => {
			const env = { ...process.env, ...more, SEEN: join(target, `seen-${Math.random()}`) };
			const child = spawn(process.execPath, [file], { cwd: target, env });
			let stdout = "";
			let stderr = "";
			child.stderr.on("data", (chunk) => {
				stderr += chunk;
			});
			child.stdout.on("data", (chunk) => {
				stdout += chunk;
			});
			// Held back for a while, as a slow reader holds the pipe full.
			child[held].pause();
			setTimeout(() => child[held].resume(), 3000);
			// Ended only once read: what the script handed on before it exited, and nothing it dropped.
			let status: number | null = null;
			child.on("exit", (code) => {
				status = code;
			});
			child[held].on("end", () => child.on("close", () => resolve({ stdout, stderr, status })));
			child.stdin.end(input);
		});
	const run = (input: string, env: Record<string, string> = {}, args: readonly string[] = []) => {
		const seen = join(target, `seen-${Math.random()}`);
		const run = spawnSync(process.execPath, [file, ...args], {
			cwd: target,
			env: { ...process.env, ...env, SEEN: seen },
			input,
			encoding: "utf8",
		});
		const read = readFile(seen, "utf8").catch(() => "");
		return read.then((text) => ({
			...run,
			seen: text
				.split("\n")
				.filter((line) => line !== "")
				.map((line) => JSON.parse(line)),
		}));
	};
	/** A run whose standard output, or error, is closed at once, as a reader that stopped reading leaves it. */
	const shut = (
		input: string,
		more: Record<string, string> = {},
		closed: "stdout" | "stderr" = "stdout",
	) =>
		new Promise<{ stderr: string; status: number | null }>((resolve) => {
			const env = { ...process.env, ...more, SEEN: join(target, `seen-${Math.random()}`) };
			const child = spawn(process.execPath, [file], { cwd: target, env });
			let stderr = "";
			child.stderr.on("data", (chunk) => {
				stderr += chunk;
			});
			child[closed].destroy();
			child.stdin.on("error", () => undefined);
			child.on("close", (status) => resolve({ stderr, status }));
			child.stdin.end(input);
		});
	return Object.assign(run, { slowly, shut, target });
}

it("settles each line as it was sent, skipping only empty lines, and counts a line longer than a subject as failed", async () => {
	const run = await script();
	const input = [" alice ", "", "bob\r", "y".repeat(255), "z".repeat(256), "down", "carol"].join(
		"\n",
	);
	const done = await run(input);
	expect(done.seen).toEqual([" alice ", "bob", "y".repeat(255), "down", "carol"]);
	expect(done.stdout).toBe(
		"marked 4 held 0 none 0 unclaimed 0 inconsistent 0 unknown 0 failed 2\n",
	);
	expect(done.status).toBe(1);
	expect(`${done.stdout}${done.stderr}`).not.toMatch(/alice|LOG/);
});

it("holds no more of an endless line than a subject may be", async () => {
	const run = await script();
	const done = await run(`${"q".repeat(4 * 1024 * 1024)}\nnext\n`);
	expect(done.seen).toEqual(["next"]);
	expect(done.stdout).toBe(
		"marked 1 held 0 none 0 unclaimed 0 inconsistent 0 unknown 0 failed 1\n",
	);
});

it("stops at an unexpected failure, telling only the counts and nothing of the failure", async () => {
	const run = await script();
	const done = await run("first\nboom\nafter\n");
	expect(done.seen).toEqual(["first", "boom"]);
	expect(done.stdout).toBe(
		"marked 1 held 0 none 0 unclaimed 0 inconsistent 0 unknown 0 failed 1\n",
	);
	expect(done.status).toBe(1);
	expect(`${done.stdout}${done.stderr}`).not.toMatch(/secret|alice|boom/);
});

it("warns once of the 0.17 variables its configuration never reads, naming none, then goes on", async () => {
	const run = await script();
	const done = await run("first\n", { LEGACY_ONE: "v1", LEGACY_TWO: "v2" });
	expect(done.stderr).toBe(
		"warn variables 0.17 read are set and never read: start the app to name them\n",
	);
	expect(done.stdout).toBe(
		"marked 1 held 0 none 0 unclaimed 0 inconsistent 0 unknown 0 failed 0\n",
	);
	expect((await run("first\n")).stderr).toBe("");
});

it("counts a subject whose factor is written and not claimed, and an answer it does not know, which fails the run", async () => {
	const run = await script();
	const claimless = await run("claimless\nfirst\n");
	expect(claimless.stdout).toBe(
		"marked 1 held 0 none 0 unclaimed 1 inconsistent 0 unknown 0 failed 0\n",
	);
	expect(claimless.status).toBe(0);
	const odd = await run("odd\nfirst\n");
	expect(odd.seen).toEqual(["odd", "first"]);
	expect(odd.stdout).toBe("marked 1 held 0 none 0 unclaimed 0 inconsistent 0 unknown 1 failed 0\n");
	expect(odd.status).toBe(1);
});

it("exits 78 on a boot another copy of the kernel refused, telling only how many refusals", async () => {
	const run = await script();
	const done = await run("first\n", { REFUSE: "1" });
	expect(done.stderr).toBe("refused 1: start the app with this configuration to read why\n");
	expect(done.status).toBe(78);
	expect(done.seen).toEqual([]);
});

it("refuses boot as config-files' check refuses, naming no variable, and exits 78", async () => {
	const run = await script();
	const done = await run("first\n", { LEGACY_ONE: "v1", APP_LEGACY_VARIABLES: "refuse" });
	expect(done.stderr).toBe("refused 1: start the app with this configuration to read why\n");
	expect(done.status).toBe(78);
	expect(done.seen).toEqual([]);
});

it("tells nothing of a boot that fails as no refusal, nor of a failure after its subjects, and exits 1", async () => {
	const run = await script();
	const boot = await run("first\n", { BOOT_FAILS: "1" });
	expect([boot.stdout, boot.stderr, boot.status]).toEqual([
		"",
		"failed: the app could not be built: start it with this configuration to read why\n",
		1,
	]);
	expect(boot.seen).toEqual([]);
	const late = await run("late\nfirst\n");
	expect(late.stderr).toBe("failed: the run stopped on an unexpected error\n");
	expect(late.status).toBe(1);
	for (const done of [boot, late])
		expect(`${done.stdout}${done.stderr}`).not.toMatch(/secret|alice/);
});

it("tells nothing a dependency writes, warns, throws or rejects while it is read or as it exits, nor a refusal it cannot count", async () => {
	for (const [runs, file] of [
		["@mod/mfa-witnessing", "src/witness-backfill.ts"],
		["@mod/mfa-reset", "src/unclaimed-factors.ts"],
	] as const) {
		const run = await script(runs, file);
		const told = async (env: Record<string, string>) => {
			const done = await run("first\n", env);
			expect(`${done.stdout}${done.stderr}`, `${file} ${JSON.stringify(env)}`).not.toMatch(
				/secret|alice/,
			);
			return done;
		};
		const thrown = await told({ IMPORT_THROWS: "1" });
		expect([thrown.stderr, thrown.status], file).toEqual([
			"failed: the app could not be built: start it with this configuration to read why\n",
			1,
		]);
		// A warning, and what a dependency writes, go nowhere: the run goes on.
		for (const env of [{ WARNS: "1" }, { CONSOLE: "1" }, { ENDS: "1" }]) {
			const done = await told(env);
			expect(done.status, `${file} ${JSON.stringify(env)}`).toBe(0);
		}
		// An exit handler that throws fails a run that ended 0, and leaves a refusal as it was.
		const exiting = await told({ EXIT_THROWS: "1" });
		expect(
			[exiting.stderr.endsWith("failed: the run stopped on an unexpected error\n"), exiting.status],
			file,
		).toEqual([true, 1]);
		const refusedExiting = await told({ EXIT_THROWS: "1", REFUSE: "1" });
		expect([refusedExiting.stderr, refusedExiting.status], file).toEqual([
			"refused 1: start the app with this configuration to read why\n",
			78,
		]);
		const rejected = await told({ REJECTS: "1", NODE_OPTIONS: "--unhandled-rejections=warn" });
		expect([rejected.stderr, rejected.status], file).toEqual([
			"failed: the run stopped on an unexpected error\n",
			1,
		]);
		// A refusal whose count cannot be read, as a number or at all, is told without it.
		for (const env of [
			{ REFUSAL_MISSHAPED: "1" },
			{ REFUSALS_THROW: "1" },
			{ LENGTH_THROWS: "1" },
		]) {
			const uncounted = await told(env);
			expect([uncounted.stderr, uncounted.status], `${file} ${JSON.stringify(env)}`).toEqual([
				"refused: start the app with this configuration to read why\n",
				78,
			]);
		}
	}
}, 60_000);

it("writes the passkey backfill alike: its own answers counted in its order, pending among them", async () => {
	const run = await script("@mod/passkey-witnessing", "src/passkey-backfill.ts");
	const done = await run("registering\nfirst\nodd\n");
	expect(done.seen).toEqual(["registering", "first", "odd"]);
	expect(done.stdout).toBe("marked 1 held 0 none 0 pending 1 inconsistent 0 unknown 1 failed 0\n");
	expect(done.status).toBe(1);
	const settled = await run("registering\nfirst\n");
	expect(settled.status).toBe(0);
});

it("names, one a line on standard output, only the subjects given whose factor stands for nothing, and counts on standard error", async () => {
	const run = await script("@mod/mfa-reset", "src/unclaimed-factors.ts");
	const done = await run("claimless-1\nfirst\n\nclaimless 2\ndown\nlast\n");
	expect(done.seen).toEqual(["claimless-1", "first", "claimless 2", "down", "last"]);
	expect(done.stdout).toBe("claimless-1\nclaimless 2\n");
	expect(done.stderr).toBe("named 2 clear 2 failed 1\n");
	expect(done.status).toBe(1);
	const clean = await run("first\n");
	expect([clean.stdout, clean.stderr, clean.status]).toEqual(["", "named 0 clear 1 failed 0\n", 0]);
	// An unexpected failure stops it, telling nothing of the failure.
	const broken = await run("boom\nclaimless-3\n");
	expect([broken.stdout, broken.stderr, broken.status]).toEqual([
		"",
		"named 0 clear 0 failed 1\n",
		1,
	]);
	// A refused boot exits 78, naming nothing.
	const refused = await run("claimless-4\n", { REFUSE: "1" });
	expect([refused.stdout, refused.stderr, refused.status]).toEqual([
		"",
		"refused 1: start the app with this configuration to read why\n",
		78,
	]);
});

it("hands on every subject it names before it exits, though the pipe it writes to is read slowly", async () => {
	const run = await script("@mod/mfa-reset", "src/unclaimed-factors.ts");
	const subjects = Array.from({ length: 10_000 }, (_, i) => `claimless-${i}-${"x".repeat(100)}`);
	const done = await run.slowly(`${subjects.join("\n")}\n`);
	expect(done.stdout.split("\n").filter((line) => line !== "")).toEqual(subjects);
	expect([done.stderr, done.status]).toEqual(["named 10000 clear 0 failed 0\n", 0]);
}, 60_000);

it("fails a run whose standard output was closed, counting no subject it could not hand on as named, and ends with its code where standard error was", async () => {
	const naming = await script("@mod/mfa-reset", "src/unclaimed-factors.ts");
	expect(await naming.shut("claimless\nfirst\n")).toEqual({
		stderr: "named 0 clear 0 failed 1\n",
		status: 1,
	});
	const counting = await script("@mod/mfa-witnessing", "src/witness-backfill.ts");
	expect(await counting.shut("first\n")).toEqual({
		stderr: "failed: the run stopped on an unexpected error\n",
		status: 1,
	});
	// Ended from the handler of an exit handler that throws, a line standard error does not take still leaves the code.
	const exiting = await counting.shut("first\n", { EXIT_THROWS: "1" }, "stderr");
	expect(exiting).toEqual({ stderr: "", status: 1 });
}, 60_000);

it("hands on every refusal of a refused boot before it exits 78, from the app's entry and the others, though standard error is read slowly", async () => {
	const lines = Array.from({ length: 5000 }, (_, i) => `refused at.${i}: ${"r".repeat(100)}`);
	for (const file of ["src/main.ts", "src/reseal.ts", "src/witness-backfill.ts"]) {
		const run = await script(
			file === "src/witness-backfill.ts" ? "@mod/mfa-witnessing" : "@mod/seal",
			file,
		);
		const done = await run.slowly("", { REFUSE_MANY: "5000" }, "stderr");
		// A script reading subjects tells how many alone; the app's entry and a call tell each.
		const told =
			file === "src/witness-backfill.ts"
				? ["refused 5000: start the app with this configuration to read why"]
				: lines;
		expect(
			done.stderr.split("\n").filter((l) => l !== ""),
			file,
		).toEqual(told);
		expect(done.status, file).toBe(78);
	}
}, 120_000);

it("hands on every line a call answers before it exits, though standard output is read slowly", async () => {
	const run = await script("@mod/seal", "src/reseal.ts");
	const done = await run.slowly("", { HOLDERS: "5000" });
	const told = done.stdout.split("\n").filter((l) => l !== "" && !l.startsWith("LOG "));
	expect(told).toHaveLength(5001);
	expect(told.at(-1)).toBe("previous keys may be retired");
	expect(done.status).toBe(0);
}, 60_000);

it.each([
	["SIGTERM", "SIGINT"],
	["SIGTERM", "SIGTERM"],
	["SIGINT", "SIGINT"],
] as const)(
	"stops the app once on a second signal that comes while it stops, waiting for the first stop (%s, then %s)",
	async (first, second) => {
		const { target } = await script("@mod/seal", "src/main.ts");
		const child = spawn(process.execPath, ["src/main.ts"], {
			cwd: target,
			env: { ...process.env, SIGNALLED: "1" },
		});
		const exited = new Promise<[number | null, string | null]>((resolve) =>
			child.once("exit", (code, signal) => resolve([code, signal])),
		);
		let output = "";
		child.stdout.on("data", (chunk) => {
			output += chunk;
			if (output.endsWith("started\n")) child.kill(first);
			if (output.endsWith("stopping\n")) child.kill(second);
		});
		child.stderr.on("data", (chunk) => {
			output += chunk;
		});
		expect(await exited, output).toEqual([0, null]);
		expect(output.split("\n").filter((l) => l !== "" && !l.startsWith("LOG "))).toEqual([
			"started",
			"stopping",
			"stopped",
		]);
	},
);

/** What a package of the fakes declares: one entry, of the tool's contract unless said. */
const declaring = (entry: Record<string, unknown>, name = "@mod/tool"): Declaring[] => [
	{
		name,
		appEntries: [{ script: "tool", shape: "call", contract: "toolRun", member: "run", ...entry }],
	},
];
const ignored = (path: string) => `node ${path}`;
const refusal = (entries: readonly Declaring[], modules = ["@mod/tool", "@mod/other"]) =>
	entriesOf(modules, (name) => name, ignored, undefined, entries);

it.each([
	["a list", [{ name: "@mod/tool", appEntries: { script: "tool" } }], "appEntries is not a list"],
	["an object", [{ name: "@mod/tool", appEntries: ["tool"] }], "an entry is not an object"],
	[
		"a script's name",
		declaring({ script: "Tool" }),
		"a script is not a lowercase name other than start",
	],
	["start", declaring({ script: "start" }), "a script is not a lowercase name other than start"],
	[
		"a shape",
		declaring({ shape: "stream" }),
		"tool's shape is not one of call, settle-subjects, name-subjects",
	],
	["a key", declaring({ fill: {} }), "tool has keys its shape does not take: fill"],
	[
		"answers on a call",
		declaring({ answers: ["done"] }),
		"tool has keys its shape does not take: answers",
	],
	[
		"answers on naming",
		declaring({ shape: "name-subjects", answers: ["done"] }),
		"keys its shape does not take: answers",
	],
	["a contract", declaring({ contract: "tool-run" }), "tool's contract is not a name"],
	["a member", declaring({ member: "run()" }), "tool's member is not a name"],
	[
		"no answers",
		declaring({ shape: "settle-subjects" }),
		"tool's answers are not a list of at least one",
	],
	[
		"empty answers",
		declaring({ shape: "settle-subjects", answers: [] }),
		"tool's answers are not a list of at least one",
	],
	[
		"a word",
		declaring({ shape: "settle-subjects", answers: ['marked"]'] }),
		"tool's answers are not each a lowercase word",
	],
	[
		"an answer twice",
		declaring({ shape: "settle-subjects", answers: ["marked", "marked"] }),
		"tool names an answer twice",
	],
	[
		"the script's own count",
		declaring({ shape: "settle-subjects", answers: ["marked", "failed"] }),
		"names an answer the script counts itself",
	],
	[
		"a script declared twice",
		[...declaring({}), ...declaring({}, "@mod/other")],
		"@mod/other declares appEntries that cannot be read: tool is declared by @mod/tool too",
	],
])("refuses a declaration that is not %s, naming its package", async (_, entries, why) => {
	const refused = await refusal(entries).catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(TypeError);
	expect((refused as Error).message).toContain("declares appEntries that cannot be read");
	expect((refused as Error).message).toContain(why);
});

it("reads only what the composed packages declare, and writes each declared script from its declaration", async () => {
	const ignoredElsewhere = await refusal([{ name: "@mod/elsewhere", appEntries: "not read" }]);
	expect(ignoredElsewhere.scripts).toEqual({});
	const declared = declaring(
		{
			script: "witness-backfill",
			shape: "settle-subjects",
			member: "settle",
			answers: ["marked", "held"],
		},
		"@mod/mfa-witnessing",
	);
	const { scripts, files } = await entriesOf(
		["@mod/mfa-witnessing"],
		(name) => name,
		ignored,
		undefined,
		declared,
	);
	expect(scripts).toEqual({ "witness-backfill": "node src/witness-backfill.ts" });
	expect(files["src/witness-backfill.ts"]).toContain(
		'const answers: readonly string[] = ["marked", "held"];',
	);
	expect(files["src/witness-backfill.ts"]).toContain("{ toolRun: declaredContract }");
});

it("calls the declared member with the arguments unread, writes its lines whole and exits with its code", async () => {
	const run = await script("@mod/tool", "src/tool.ts", declaring({}));
	const done = await run("", {}, ["--flag", "value"]);
	expect(done.stdout.split("\n").filter((l) => !l.startsWith("LOG "))).toEqual([
		'args ["--flag","value"]',
		"done",
		"",
	]);
	expect(done.stderr).toBe("");
	expect(done.status).toBe(0);
	const silent = await run("", { TOOL_SILENT: "1" });
	expect(silent.stdout.split("\n").filter((l) => l !== "" && !l.startsWith("LOG "))).toEqual([]);
	expect(silent.status).toBe(0);
	const passed = await run("", { TOOL_CODE: "77" });
	expect(passed.stdout).toContain("told\n");
	expect(passed.status).toBe(77);
}, 60_000);

it.each([
	[
		"78, which is a refused boot's",
		{ TOOL_CODE: "78" },
		"failed: the run answered a code this script does not pass on",
	],
	["past 78", { TOOL_CODE: "300" }, "failed: the run answered a code this script does not pass on"],
	["below 0", { TOOL_CODE: "-1" }, "failed: the run answered a code this script does not pass on"],
	[
		"not whole",
		{ TOOL_CODE: "2.5" },
		"failed: the run answered a code this script does not pass on",
	],
	[
		"not a number",
		{ TOOL_CODE: '"2"' },
		"failed: the run answered a code this script does not pass on",
	],
	[
		"lines that are not a list",
		{ TOOL_MISSHAPED: "1" },
		"failed: the run's answer could not be read",
	],
	["a throw", { TOOL_THROWS: "1" }, "failed: the run stopped on an unexpected error"],
	["nothing", { TOOL_ANSWER: "null" }, "failed: the run's answer could not be read"],
	["no object", { TOOL_ANSWER: '"secret of alice"' }, "failed: the run's answer could not be read"],
	[
		"no code",
		{ TOOL_ANSWER: '{"lines":[]}' },
		"failed: the run answered a code this script does not pass on",
	],
])(
	"exits 1 on a call answering %s, with a fixed line and nothing of the answer",
	async (_, env, line) => {
		const run = await script("@mod/tool", "src/tool.ts", declaring({}));
		const done = await run("", env);
		expect(done.stderr).toBe(`${line}\n`);
		expect(done.stdout).not.toContain("told");
		expect(`${done.stdout}${done.stderr}`).not.toContain("alice");
		expect(done.status).toBe(1);
	},
	60_000,
);

it("exits 78 on a refused boot of a call, as the app's entry does", async () => {
	const run = await script("@mod/tool", "src/tool.ts", declaring({}));
	const done = await run("", { REFUSE: "1" });
	expect(done.stderr).toBe("refused a.b: why\n");
	expect(done.stdout.split("\n").filter((l) => l !== "" && !l.startsWith("LOG "))).toEqual([]);
	expect(done.status).toBe(78);
}, 60_000);

it("names the subjects a declared member answers above 0 for, through the member the package names", async () => {
	const declared = declaring({ script: "flagged", shape: "name-subjects", member: "check" });
	const run = await script("@mod/tool", "src/flagged.ts", declared);
	const done = await run("flagged-1\nclear\nflagged-2\n");
	expect(done.stdout).toBe("flagged-1\nflagged-2\n");
	expect(done.stderr).toBe("named 2 clear 1 failed 0\n");
	expect(done.seen).toEqual(["flagged-1", "clear", "flagged-2"]);
	expect(done.status).toBe(0);
}, 60_000);

it("takes the declared contract under a name of its own, so one named as a script's own name works", async () => {
	const called = await script("@mod/tool", "src/tool.ts", declaring({ contract: "lines" }));
	const told = await called("", {}, ["--x"]);
	expect(told.stdout).toContain('args ["--x"]\n');
	expect(told.status).toBe(0);
	const settled = declaring({
		script: "settled",
		shape: "settle-subjects",
		contract: "end",
		member: "settle",
		answers: ["marked"],
	});
	const settling = await script("@mod/tool", "src/settled.ts", settled);
	const counted = await settling("first\n");
	expect(counted.stdout).toBe("marked 1 unknown 0 failed 0\n");
	expect(counted.status).toBe(0);
	const named = declaring({
		script: "named",
		shape: "name-subjects",
		contract: "tell",
		member: "check",
	});
	const naming = await script("@mod/tool", "src/named.ts", named);
	const found = await naming("flagged-1\nclear\n");
	expect(found.stdout).toBe("flagged-1\n");
	expect(found.status).toBe(0);
}, 60_000);
