import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { workspacePackages } from "@mod/workspace-packages";

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
		/** Contracts it exports, by name, and the packages alone that may import each. */
		readonly takenBy?: unknown;
		/** A writer's declaration of the property it writes (G32). */
		readonly narrower?: unknown;
		/** What an owner holds to declaration, `{ type, property }` (G32). */
		readonly narrowerOwner?: unknown;
		/** The one shipped file that may start a helper process, mapped to the helper's file (guard's G26). */
		readonly forks?: unknown;
		readonly exports?: Record<string, string>;
		readonly dependencies?: Record<string, string>;
		readonly peerDependencies?: Record<string, string>;
		readonly devDependencies?: Record<string, string>;
	};
	readonly card: string | undefined;
	/** Paths relative to the package, without node_modules. */
	readonly files: readonly string[];
}

function walk(dir: string, base = dir): string[] {
	return readdirSync(dir).flatMap((entry) => {
		if (entry === "node_modules" || entry.startsWith(".")) return [];
		const path = join(dir, entry);
		return statSync(path).isDirectory() ? walk(path, base) : [relative(base, path)];
	});
}

/** Workspace packages as `workspace-packages` lists them: the root left out, each directory a real path. */
export function readWorkspace(root: string): Pkg[] {
	return workspacePackages(root).map((entry) => {
		const files = walk(entry.dir);
		return {
			name: entry.name,
			dir: entry.dir,
			manifest: JSON.parse(readFileSync(join(entry.dir, "package.json"), "utf8")),
			card: files.includes("README.md")
				? readFileSync(join(entry.dir, "README.md"), "utf8")
				: undefined,
			files,
		};
	});
}
