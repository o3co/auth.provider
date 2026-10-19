import { readFileSync } from "node:fs";

/** A module as the published bundles hold it: the bundle to depend on, and the path its entries import under. */
export interface Published {
	readonly name: string;
	readonly package: string;
	readonly entry: string;
}

/** Each module's published bundle and entry, by name, from the index a bundle carries. */
export function publishedInIndex(file: string): ReadonlyMap<string, Published> {
	const index = JSON.parse(readFileSync(file, "utf8")) as { packages: readonly Published[] };
	return new Map(
		index.packages.map(({ name, package: bundle, entry }) => [
			name,
			Object.freeze({ name, package: bundle, entry }),
		]),
	);
}

/**
 * The names given as published, in their order. Refuses, naming each, a name no bundle publishes;
 * and every name where there is no index, in the workspace, where each name imports as itself.
 */
export function publishedWith(
	index: ReadonlyMap<string, Published> | undefined,
	names: readonly string[],
): Published[] {
	if (index === undefined) {
		throw new Error(
			"nothing is published here: in the workspace, every module imports under its own name",
		);
	}
	const absent = names
		.filter((n, i, all) => all.indexOf(n) === i && !index.has(n))
		.map((n) => `${n}: not published`);
	if (absent.length > 0) throw new Error(absent.join("; "));
	return names.map((name) => index.get(name) as Published);
}
