/** The local layer that boots a generated app for a test or a conformance run, from its modules' trial files. */
import { execFileSync } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { parse } from "@o3co/ts.hocon";

/** The file beside a package's manifest that holds the values a trial boots its module on. */
export const trialFile = "trial.conf";

/** The file beside a package's manifest that holds its section's example, whose root names the section. */
const fragmentFile = "config.example";

/** What every app composes, whether its entry imports it as a module or not. */
const kernel = "@mod/kernel";

type Tree = { readonly [key: string]: unknown };

/** A reading's catch: a missing file reads as `undefined`, and any other failure is thrown on. */
const missing = (error: NodeJS.ErrnoException): undefined => {
	if (error.code === "ENOENT") return undefined;
	throw error;
};

const isTree = (value: unknown): value is Tree =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** One composed module's trial file, and the sections it may write. */
export interface Trial {
	readonly from: string;
	readonly text: string;
	/** Its own section, which it sets as it likes. */
	readonly own?: string;
	/** The sections of what it depends on, whose lists it may only append to. */
	readonly depended: readonly string[];
}

/** Each leaf of a tree with its path: objects are walked into, lists and scalars are leaves. */
const leaves = (tree: Tree, path: readonly string[]): [string[], unknown][] =>
	Object.entries(tree).flatMap(([key, value]) =>
		isTree(value) ? leaves(value, [...path, key]) : [[[...path, key], value]],
	);

const at = (tree: unknown, path: readonly string[]): unknown =>
	path.reduce((value, key) => (isTree(value) ? value[key] : undefined), tree);

/** What stands first in a list a trial file must append to, so that one it replaced shows. */
const probe = "TRIAL-PROBE";

/** Refuses a trial file that sets a section not its own, or a depended-on one but by appending to its lists. */
function check(trial: Trial): void {
	const tree = parse(trial.text).toObject() as Tree;
	const appended: string[][] = [];
	for (const [section, value] of Object.entries(tree)) {
		if (section === trial.own) continue;
		if (!trial.depended.includes(section)) {
			throw new Error(
				`${trial.from} sets ${section}, neither its own section nor one of what it depends on`,
			);
		}
		for (const [path, leaf] of leaves({ [section]: value }, [])) {
			if (!Array.isArray(leaf)) throw appendOnly(trial, path);
			appended.push(path);
		}
	}
	const prefix = appended.map(
		(path) => `${path.map((k) => JSON.stringify(k)).join(".")} = [${probe}]`,
	);
	const probed = parse([...prefix, trial.text].join("\n")).toObject();
	const replaced = appended.find((path) => (at(probed, path) as unknown[])[0] !== probe);
	if (replaced) throw appendOnly(trial, replaced);
}

const appendOnly = (trial: Trial, path: readonly string[]) =>
	new Error(`${trial.from} may only append to ${path.join(".")}, a section of what it depends on`);

/**
 * The trials read as one document, each checked first, then the caller's layer: given in order,
 * what is depended on first, so a later file's and the layer's appends join the lists before them.
 */
export function trialTree(trials: readonly Trial[], layer = ""): Tree {
	for (const trial of trials) check(trial);
	return parse([...trials.map((t) => t.text), layer].join("\n")).toObject() as Tree;
}

/** The marks a trial file may give as a value, each made at each call. */
const marks = (redisUrl: string): ReadonlyMap<string, () => string> =>
	new Map([
		[
			"TRIAL-FRESH-ED25519-PKCS8-PEM",
			() =>
				generateKeyPairSync("ed25519")
					.privateKey.export({ type: "pkcs8", format: "pem" })
					.toString(),
		],
		[
			"TRIAL-FRESH-RSA-2048-PKCS8-PEM",
			() =>
				generateKeyPairSync("rsa", { modulusLength: 2048 })
					.privateKey.export({ type: "pkcs8", format: "pem" })
					.toString(),
		],
		["TRIAL-FRESH-32-BYTES-BASE64", () => randomBytes(32).toString("base64")],
		["TRIAL-FRESH-32-BYTES-BASE64URL", () => randomBytes(32).toString("base64url")],
		["TRIAL-REDIS-URL", () => redisUrl],
	]);

function marked(value: unknown, made: ReadonlyMap<string, () => string>): unknown {
	if (typeof value === "string") return made.get(value)?.() ?? value;
	if (Array.isArray(value)) return value.map((v) => marked(v, made));
	if (isTree(value)) {
		return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, marked(v, made)]));
	}
	return value;
}

/** The workspace the trial files are read from, once a run. */
const ownWorkspace = join(import.meta.dirname, "..", "..", "..", "..");
let packages: Map<string, string> | undefined;
/** Package directories by name, as the workspace definition places them. */
const workspace = () => {
	packages ??= new Map(
		(
			JSON.parse(
				execFileSync("pnpm", ["ls", "-r", "--json", "--depth", "-1"], {
					cwd: ownWorkspace,
					encoding: "utf8",
				}),
			) as { name: string; path: string }[]
		).map((entry) => [entry.name, entry.path]),
	);
	return packages;
};

/** A package's section, from the root of its fragment; none without one. */
async function sectionOf(dir: string): Promise<string | undefined> {
	const text = await readFile(join(dir, fragmentFile), "utf8").catch(missing);
	return text === undefined ? undefined : Object.keys(parse(text).toObject() as Tree)[0];
}

/** The trials of the packages named, each after those it depends on; a package without one is skipped. */
async function trialsOf(names: readonly string[]): Promise<Trial[]> {
	const dirs = workspace();
	const ordered: string[] = [];
	const seen = new Set<string>();
	const visit = async (name: string) => {
		const dir = dirs.get(name);
		if (dir === undefined || seen.has(name)) return;
		seen.add(name);
		for (const dependency of await dependenciesOf(dir)) {
			if (names.includes(dependency)) await visit(dependency);
		}
		ordered.push(name);
	};
	for (const name of names) await visit(name);
	const trials: Trial[] = [];
	for (const name of ordered) {
		const dir = dirs.get(name) as string;
		const from = join(dir, trialFile);
		const text = await readFile(from, "utf8").catch(missing);
		if (text === undefined) continue;
		const depended = await Promise.all(
			(await dependenciesOf(dir)).flatMap((d) => {
				const at = dirs.get(d);
				return at === undefined ? [] : [sectionOf(at)];
			}),
		);
		const own = await sectionOf(dir);
		trials.push({
			from,
			text,
			...(own === undefined ? {} : { own }),
			depended: depended.filter((s) => s !== undefined),
		});
	}
	return trials;
}

/** Every trial file in the workspace, each with the sections it may write. */
export const workspaceTrials = () => trialsOf([...workspace().keys()]);

const dependenciesOf = async (dir: string): Promise<string[]> =>
	Object.keys(JSON.parse(await readFile(join(dir, "package.json"), "utf8")).dependencies ?? {});

/** The packages an app's entry imports modules from, by their directory's name, as the workspace or a bundle names them. */
async function composedIn(target: string): Promise<string[]> {
	const entry = await readFile(join(target, "src", "main.ts"), "utf8");
	const dirs = [...entry.matchAll(/from "(?:[^"]*\/)?([a-z0-9-]+)\/module"/g)].map(
		(found) => found[1] as string,
	);
	const byDir = new Map([...workspace()].map(([name, dir]) => [basename(dir), name]));
	return [kernel, ...dirs.flatMap((dir) => byDir.get(dir) ?? [])];
}

/**
 * The local layer that boots the app generated in `target` for a test or a conformance run: the
 * trial file of each module its entry imports, and the kernel's, then the caller's `layer`, read
 * as one HOCON document; the sections in `leave` are dropped. Marks are made fresh at each call.
 */
export async function trialLayer(
	target: string,
	settings: {
		readonly redisUrl: string;
		readonly leave?: readonly string[];
		readonly layer?: string;
	},
): Promise<string> {
	const tree = trialTree(await trialsOf(await composedIn(target)), settings.layer);
	const kept = Object.entries(tree).filter(([section]) => !settings.leave?.includes(section));
	const made = marked(Object.fromEntries(kept), marks(settings.redisUrl));
	return `${JSON.stringify(made, null, "\t")}\n`;
}
