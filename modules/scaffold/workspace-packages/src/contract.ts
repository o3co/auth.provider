import { execFileSync } from "node:child_process";
import { type Dirent, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";

/** A package of a workspace: its name and its directory, a real path. */
export interface WorkspacePackage {
	readonly name: string;
	readonly dir: string;
}

/**
 * The packages `root`'s workspace definition places, the root left out, in order of directory.
 * Patterns of whole names and one-level `*`, each perhaps negated, are read here; any other
 * definition is pnpm's to read, as `pnpm ls -r` lists it.
 */
export function workspacePackages(root: string): WorkspacePackage[] {
	const real = realpathSync(root);
	const listed = readHere(real) ?? listedByPnpm(real);
	return listed
		.filter((p) => p.dir !== real)
		.toSorted((a, b) => (a.dir < b.dir ? -1 : a.dir > b.dir ? 1 : 0));
}

/** A segment read here: a whole name, not hidden, or `*`. */
const plainSegment = /^(\*|[\w@-][\w.@-]*)$/;

/** The packages the definition places, where every pattern is one read here; else nothing. */
function readHere(root: string): WorkspacePackage[] | undefined {
	let text: string;
	try {
		text = readFileSync(join(root, "pnpm-workspace.yaml"), "utf8");
	} catch {
		return undefined;
	}
	const patterns = (parse(text) as { packages?: unknown } | null)?.packages;
	if (!Array.isArray(patterns) || patterns.length === 0) return undefined;
	const read: { readonly negated: boolean; readonly segments: string[] }[] = [];
	for (const pattern of patterns) {
		if (typeof pattern !== "string") return undefined;
		const negated = pattern.startsWith("!");
		const segments = (negated ? pattern.slice(1) : pattern).replace(/^\.\//, "").split("/");
		if (!segments.every((s) => plainSegment.test(s))) return undefined;
		read.push({ negated, segments });
	}
	const left = new Set(read.filter((p) => p.negated).flatMap((p) => dirsAt(root, p.segments)));
	const dirs = new Set(read.filter((p) => !p.negated).flatMap((p) => dirsAt(root, p.segments)));
	const found: WorkspacePackage[] = [];
	for (const dir of dirs) {
		if (left.has(dir)) continue;
		let manifest: { name?: unknown };
		try {
			manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
		} catch {
			continue;
		}
		// A package with no name is pnpm's to list as it does.
		if (typeof manifest.name !== "string") return undefined;
		found.push({ name: manifest.name, dir: realpathSync(dir) });
	}
	return found;
}

/** The directories the segments reach from `root`, a `*` taking every directory not hidden nor `node_modules`. */
function dirsAt(root: string, segments: readonly string[]): string[] {
	let dirs = [root];
	for (const segment of segments) {
		dirs = dirs.flatMap((dir) =>
			segment === "*"
				? entriesOf(dir)
						.filter((e) => !e.name.startsWith(".") && e.name !== "node_modules")
						.map((e) => join(dir, e.name))
						.filter(isDir)
				: [join(dir, segment)].filter(isDir),
		);
	}
	return dirs;
}

const entriesOf = (dir: string): Dirent[] => {
	try {
		return readdirSync(dir, { withFileTypes: true });
	} catch {
		return [];
	}
};

const isDir = (path: string) => {
	try {
		return statSync(path).isDirectory();
	} catch {
		return false;
	}
};

/** The packages as pnpm lists the workspace at `root`; with no definition, it writes a list per package. */
function listedByPnpm(root: string): WorkspacePackage[] {
	const out = execFileSync("pnpm", ["ls", "-r", "--json", "--depth", "-1"], {
		cwd: root,
		encoding: "utf8",
	});
	const lists = JSON.parse(`[${out.trim().replaceAll(/\]\s*\[/g, "],[")}]`) as {
		name: string;
		path: string;
	}[][];
	return lists.flat().map((entry) => ({ name: entry.name, dir: entry.path }));
}
