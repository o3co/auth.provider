import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { type Fragment, fragmentsIn, fragmentsOf } from "./fragments.ts";
import { dependenciesOf, workspacePackages } from "./project.ts";

/** Where the packages an app assembles come from, and how the app names them. */
export interface Packages {
	/** Each name's section example, in the order given; a package without one is skipped. */
	fragments(names: readonly string[]): Promise<Fragment[]>;
	/** What the app depends on to have the names. */
	dependencies(names: readonly string[]): Record<string, string>;
	/** What the app imports a name's entries under. */
	importOf(name: string): string;
}

interface Indexed {
	readonly version: string;
	readonly packages: readonly {
		readonly name: string;
		readonly package: string;
		readonly entry: string;
		readonly fragment?: string;
	}[];
}

/** The index distribution writes at the root of the bundle create-app is built into. */
const bundleIndex = join(import.meta.dirname, "..", "..", "index.json");
/** The workspace this package lies in, where `combinations` reads the modules it composes. */
const ownWorkspace = join(import.meta.dirname, "..", "..", "..", "..");

/**
 * The packages as published, from the index, where create-app is built into a bundle and no
 * workspace is given; else the workspace's, linked when one is given.
 */
export function packagesFor(plan: { readonly workspace?: string }, index = bundleIndex): Packages {
	if (plan.workspace === undefined && existsSync(index)) {
		return publishedIn(JSON.parse(readFileSync(index, "utf8")) as Indexed);
	}
	const dirs = workspacePackages(resolve(plan.workspace ?? ownWorkspace));
	return {
		fragments: (names) => fragmentsIn(names.flatMap((name) => dirs.get(name) ?? [])),
		dependencies: (names) => dependenciesOf(names, plan.workspace ? dirs : undefined),
		importOf: (name) => name,
	};
}

function publishedIn(index: Indexed): Packages {
	const byName = new Map(index.packages.map((entry) => [entry.name, entry]));
	const found = (name: string) => {
		const entry = byName.get(name);
		if (!entry) throw new Error(`${name} is no published package`);
		return entry;
	};
	return {
		fragments: async (names) =>
			fragmentsOf(
				names.flatMap((name) => {
					const { fragment } = found(name);
					return fragment === undefined ? [] : [{ from: name, text: fragment }];
				}),
			),
		dependencies: (names) =>
			Object.fromEntries(names.map((name) => [found(name).package, index.version])),
		importOf: (name) => found(name).entry,
	};
}
