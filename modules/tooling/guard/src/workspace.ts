import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

export interface Pkg {
	readonly name: string;
	readonly dir: string;
	readonly manifest: {
		/** The package's kind, as the budget's kinds name it. */
		readonly kind?: string;
		/** Whether the package's store interfaces must be wired. */
		readonly storeWiring?: boolean;
		/** The package whose store interfaces this wiring ties to an implementation. */
		readonly wires?: string;
		/** The axis owner an adapter stands in for, or contributes to; one of the two. */
		readonly replaces?: unknown;
		readonly adapts?: unknown;
		/** Whether an adapter is its axis's default; only `true`. */
		readonly default?: unknown;
		/** Whether a feature is left off the full template; only `true`. */
		readonly optIn?: unknown;
		readonly joins?: unknown;
		/** Whether features keep data only through a wiring built on it, never depending on it; only `true`. */
		readonly forWiring?: unknown;
		/** The dependencies it takes functions and types from alone, never a contract. */
		readonly helpers?: unknown;
		/** The words naming how its shipped code reaches the network, other than through outbound. */
		readonly network?: string | readonly string[];
		readonly exports?: Record<string, string>;
		readonly dependencies?: Record<string, string>;
		readonly peerDependencies?: Record<string, string>;
		readonly devDependencies?: Record<string, string>;
	};
	readonly card: string | undefined;
	/** Paths relative to the package, without node_modules. */
	readonly files: readonly string[];
}

export interface Doc {
	readonly path: string;
	readonly text: string;
}

function walk(dir: string, base = dir): string[] {
	return readdirSync(dir).flatMap((entry) => {
		if (entry === "node_modules" || entry.startsWith(".")) return [];
		const path = join(dir, entry);
		return statSync(path).isDirectory() ? walk(path, base) : [relative(base, path)];
	});
}

/** Workspace packages as pnpm sees them, minus the root. */
export function readWorkspace(root: string): Pkg[] {
	const listed = JSON.parse(
		execFileSync("pnpm", ["ls", "-r", "--json", "--depth", "-1"], { cwd: root, encoding: "utf8" }),
	) as { name: string; path: string }[];
	return listed
		.filter((entry) => entry.path !== root)
		.map((entry) => {
			const files = walk(entry.path);
			return {
				name: entry.name,
				dir: entry.path,
				manifest: JSON.parse(readFileSync(join(entry.path, "package.json"), "utf8")),
				card: files.includes("README.md")
					? readFileSync(join(entry.path, "README.md"), "utf8")
					: undefined,
				files,
			};
		});
}

/** Every Markdown document in the repository, without node_modules. */
export function readDocuments(root: string): Doc[] {
	return walk(root)
		.filter((file) => file.endsWith(".md"))
		.map((file) => ({ path: join(root, file), text: readFileSync(join(root, file), "utf8") }));
}
