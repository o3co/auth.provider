/** What every generated deployment is held to, full or a pattern: its configuration and its boot. */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import { parseEnv } from "node:util";
import { configFiles, kernel } from "@mod/app-output";
import { parse } from "@o3co/ts.hocon";
import { expect } from "vitest";
import { packageDirs as dirs, leaves, read, type Tree } from "./full-app.ts";

export interface Manifest {
	name: string;
	kind?: string;
	optIn?: boolean;
	replaces?: string;
	adapts?: string;
	default?: boolean;
	wires?: string;
	joins?: string[];
	exports?: Record<string, string>;
}
export const manifest = (name: string): Manifest =>
	JSON.parse(readFileSync(join(dirs.get(name) ?? "", "package.json"), "utf8"));

export { configFiles, kernel };

/** The plan's exception: a value that spans sections, in a fragment for its schema only. */
const spansSections = "audit.receivers";

/** The fragments' leaves of the packages named, by dotted key. */
function fragmentLeaves(names: readonly string[]): Map<string, unknown> {
	return new Map(
		names.flatMap((name) => {
			const file = join(dirs.get(name) ?? "", "config.example");
			if (!existsSync(file)) return [];
			const tree = parse(readFileSync(file, "utf8")).toObject() as Tree;
			return leaves(tree).map(([path, value]) => [path.join("."), value] as const);
		}),
	);
}

export const envOf = (key: string) => key.replaceAll(".", "_").replaceAll("-", "_").toUpperCase();

/** Each scalar of the modules' fragments is read from env, one variable each, and the files hold no value. */
/** A value its owner's example gives in several lines, which a one-line env file cannot hold. */
const severalLines = (value: unknown) => typeof value === "string" && value.includes("\n");

export async function readsScalarsFromEnv(target: string, modules: readonly string[]) {
	const fragment = fragmentLeaves([kernel, ...modules]);
	const scalars = [...fragment].filter(
		([key, value]) => !Array.isArray(value) && key !== spansSections,
	);
	expect(scalars.length).toBeGreaterThan(0);
	const application = await read(target, "config/application.conf");
	// Each variable set to its own name shows which key reads it.
	const named = Object.fromEntries(scalars.map(([key]) => [envOf(key), envOf(key)]));
	const reading = leaves(parse(application, { env: named }).toObject() as Tree);
	expect(reading.map(([path, value]) => [path.join("."), value])).toEqual(
		scalars.map(([key]) => [key, envOf(key)]),
	);
	expect([...application.matchAll(/\$\{\?([A-Z0-9_]+)\}/g)]).toHaveLength(scalars.length);
	// With no environment, the file holds nothing.
	expect(leaves(parse(application, { env: {} }).toObject() as Tree)).toEqual([]);
	// No live value line, so a copy sets nothing until a line is uncommented.
	const envText = await read(target, ".env.example");
	expect(parseEnv(envText)).toEqual({});
	const env = envText.split("\n").filter((line) => line !== "");
	expect(env.filter((line) => !line.startsWith("#"))).toEqual([]);
	const unquoted = (value: string) => (value.startsWith('"') ? JSON.parse(value) : value);
	expect(
		env.flatMap((line) => {
			const m = /^# ([A-Z0-9_]+)=(.*)$/.exec(line);
			return m ? [[m[1], unquoted(m[2] ?? "")]] : [];
		}),
	).toEqual(
		scalars
			.filter(([, value]) => !severalLines(value))
			.map(([key, value]) => [envOf(key), String(value)]),
	);
	const readme = await read(target, "README.md");
	// Each scalar has its row; how a row of several lines reads is app-output's to test.
	for (const [key] of scalars) expect(readme).toContain(`| \`${key}\` | \`${envOf(key)}\``);
}

/** The fragments' lists, and a value spanning sections, go to the local layer's example as comments only. */
export async function writesListsLocally(target: string, modules: readonly string[]) {
	const fragment = fragmentLeaves([kernel, ...modules]);
	const lists = [...fragment].filter(([, value]) => Array.isArray(value) || severalLines(value));
	expect(lists.length).toBeGreaterThan(0);
	const example = await read(target, "config/local.conf.example");
	// No live value line, so a copy sets nothing until a key is uncommented.
	expect(example.split("\n").filter((line) => line !== "" && !line.startsWith("#"))).toEqual([]);
	expect(parse(example).toObject()).toEqual({});
	// Uncommented, each list holds its fragment's placeholders, and the spanning value the operator's.
	const uncommented = new Map(
		leaves(parse(example.replace(/^# /gm, "")).toObject() as Tree).map(([path, value]) => [
			path.join("."),
			value,
		]),
	);
	expect([...uncommented].filter(([key]) => key !== spansSections)).toEqual(lists);
	expect(uncommented.get(spansSections)).toEqual([expect.stringMatching(/^REPLACE-[A-Z-]+$/)]);
	expect(example).toMatch(/^# audit\.receivers = \[REPLACE-[A-Z-]+\]$/m);
	const env = await read(target, ".env.example");
	expect(env).not.toContain(envOf(spansSections));
	const readme = await read(target, "README.md");
	for (const [key] of lists) expect(readme).toContain(`\`${key}\``);
	expect(readme).toContain(`\`${spansSections}\``);
}

/** The app's refusals, by where, booted on these files and this environment alone. */
export function boot(target: string, files: string, env: Record<string, string> = {}) {
	const run = spawnSync(process.execPath, ["src/main.ts"], {
		cwd: target,
		env: { ...env, APP_CONFIG: files },
		encoding: "utf8",
	});
	const refused = [...run.stderr.matchAll(/^refused ([^:]+): /gm)].map((m) => m[1] ?? "");
	return { status: run.status, refused, stderr: run.stderr };
}

/** An empty configuration is refused only for the modules' sections and the kernel's; its refusals. */
export async function refusesEmptyOnlyForSections(target: string, modules: readonly string[]) {
	await writeFile(join(target, "empty.conf"), "");
	const sections = new Set(["kernel"]);
	for (const name of modules) {
		const entry = manifest(name).exports?.["./module"] ?? "";
		sections.add(
			((await import(join(dirs.get(name) ?? "", entry))).default as { name: string }).name,
		);
	}
	const empty = boot(target, "empty.conf");
	expect(empty.status, empty.stderr).toBe(78);
	expect(empty.refused.length).toBeGreaterThan(0);
	for (const where of empty.refused) expect(sections, where).toContain(where.split(".")[0]);
	return empty.refused;
}

/** The generated configuration alone is refused only for keys the guide names; its refusals. */
export async function refusesGeneratedOnlyForNamedKeys(target: string) {
	const generatedOnly = boot(target, "config/application.conf");
	expect(generatedOnly.status, generatedOnly.stderr).toBe(78);
	const named = [
		...(await read(target, "README.md")).matchAll(/`([a-z0-9-]+(?:\.[a-z0-9-]+)+)`/g),
	].map((m) => m[1] ?? "");
	for (const where of generatedOnly.refused) {
		expect(
			named.some((key) => key === where || key.startsWith(`${where}.`)),
			where,
		).toBe(true);
	}
	return generatedOnly.refused;
}

export async function freePort(): Promise<number> {
	return new Promise((resolve) => {
		const server = createServer().listen(0, "127.0.0.1", () => {
			const address = server.address();
			server.close(() => resolve(typeof address === "object" && address ? address.port : 0));
		});
	});
}

/** Runs the app until it says it listens, then stops it by SIGTERM: its exit code and output. */
export async function startsAndStops(target: string) {
	const child = spawn(process.execPath, ["src/main.ts"], {
		cwd: target,
		env: { APP_CONFIG: "config/local.conf,config/application.conf" },
	});
	let output = "";
	const exited = new Promise<number | null>((resolve) => child.once("exit", resolve));
	const listening = new Promise<void>((resolve) => {
		const seen = (chunk: Buffer) => {
			output += chunk;
			if (output.includes('"event":"http.listening"')) resolve();
		};
		child.stdout.on("data", seen);
		child.stderr.on("data", seen);
	});
	await Promise.race([listening, exited]);
	child.kill("SIGTERM");
	return { code: await exited, output };
}
