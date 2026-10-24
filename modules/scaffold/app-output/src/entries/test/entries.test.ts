import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { configFiles, kernel } from "../../project.ts";
import { entriesOf } from "../contract.ts";

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
	// Without the script's own runtime, the composed sink would write this line.
	(runtime?.log ?? { warn: (event) => process.stdout.write(\`LOG \${event}\\n\`) }).warn("fake.assembled");
	const { backfill } = await import("fake-witnessing");
	return { get: () => backfill, stop: async () => {} };
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
export const backfill = {
	settle: async (subject) => {
		appendFileSync(process.env.SEEN, \`\${JSON.stringify(subject)}\\n\`);
		if (subject === "down") throw Object.assign(new Error("down for alice"), { name: "Unavailable" });
		if (subject === "boom") throw new Error("secret of alice");
		if (subject === "claimless") return "unclaimed";
		if (subject === "registering") return "pending";
		if (subject === "odd") return "a word of a later release";
		return "marked";
	},
};`,
		"module.js": "export default {};",
	},
};

/** The entry `runs` calls for, written over the fakes; a run of it on an input. */
async function script(runs = "@mod/mfa-witnessing", file = "src/witness-backfill.ts") {
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
	const { files } = await entriesOf([runs], importOf, (path) => `node ${path}`);
	await mkdir(join(target, "src"));
	await writeFile(join(target, file), files[file] ?? "");
	return (input: string, env: Record<string, string> = {}) => {
		const seen = join(target, `seen-${Math.random()}`);
		const run = spawnSync(process.execPath, [file], {
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

it("warns once of the 0.17 variables its configuration never reads, then goes on", async () => {
	const run = await script();
	const done = await run("first\n", { LEGACY_ONE: "v1", LEGACY_TWO: "v2" });
	expect(done.stderr).toBe("warn config-files: 2 named: LEGACY_ONE, LEGACY_TWO\n");
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

it("exits 78 on a boot another copy of the kernel refused, writing each refusal", async () => {
	const run = await script();
	const done = await run("first\n", { REFUSE: "1" });
	expect(done.stderr).toBe("refused a.b: why\n");
	expect(done.status).toBe(78);
	expect(done.seen).toEqual([]);
});

it("refuses boot as config-files' check refuses, writing the refusal and exiting 78", async () => {
	const run = await script();
	const done = await run("first\n", { LEGACY_ONE: "v1", APP_LEGACY_VARIABLES: "refuse" });
	expect(done.stderr).toBe("refused config-files: LEGACY_ONE\n");
	expect(done.status).toBe(78);
	expect(done.seen).toEqual([]);
});

it("writes the passkey backfill alike: its own answers counted in its order, pending among them", async () => {
	const run = await script("@mod/passkey-witnessing", "src/passkey-backfill.ts");
	const done = await run("registering\nfirst\nodd\n");
	expect(done.seen).toEqual(["registering", "first", "odd"]);
	expect(done.stdout).toBe("marked 1 held 0 none 0 pending 1 inconsistent 0 unknown 1 failed 0\n");
	expect(done.status).toBe(1);
	const settled = await run("registering\nfirst\n");
	expect(settled.status).toBe(0);
});
