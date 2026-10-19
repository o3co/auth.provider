import { existsSync } from "node:fs";
import { join } from "node:path";
import {
	addableOf,
	completedOf,
	composedWith,
	fullWith,
	neededWith,
	optInsOf,
	type Selection,
} from "./composed.ts";
import { type Declared, declaredIn, declaredInIndex } from "./declared.ts";
import { type Published, publishedInIndex, publishedWith } from "./published.ts";

export type { Selection } from "./composed.ts";
export { type Kind, kinds } from "./kinds.ts";
export type { Published } from "./published.ts";

let workspace: Declared | undefined;
/** The index at a bundle's root, where combinations is built into one. */
const bundleIndex = join(import.meta.dirname, "..", "..", "index.json");

/** The modules given (owners a declared default replaces swapped for it), then their wirings and bridges, each once, first named first. */
export function completed(modules: readonly string[]): string[] {
	return completedOf(declared(), modules);
}

/** Read once: built into a bundle, the index at its root; in the workspace, the workspace itself. */
const declared = () => {
	workspace ??= existsSync(bundleIndex)
		? declaredInIndex(bundleIndex)
		: declaredIn(join(import.meta.dirname, "..", "..", "..", ".."));
	return workspace;
};

/** What a selection composes (see `composedWith`); refuses, naming each, what cannot be selected. */
export const composed = (selection: Selection): string[] => composedWith(declared(), selection);

/** The full template: every foundation and feature that does not opt in, with each default, and what is added. */
export const full = (add?: readonly string[]): string[] => fullWith(declared(), add);

/** The features that opt in, which the full template leaves out until added. */
export const optIns = (): string[] => optInsOf(declared());

/** The names a selection or the full template may add, in code point order. */
export const addable = (): string[] => addableOf(declared());

/** The modules given, what they need to run, then `completed`, as `composed` reaches them but with no axis default. */
export const needed = (modules: readonly string[]): string[] => neededWith(declared(), modules);

let bundle: ReadonlyMap<string, Published> | undefined;

/**
 * The names given (as `composed`, `needed` and `full` give them) as published: each one's bundle and
 * the path its entries import under, in the order given. Built into a bundle only: in the workspace,
 * where nothing is published, it refuses; it refuses a name no bundle publishes, naming each.
 */
export function published(names: readonly string[]): Published[] {
	if (existsSync(bundleIndex)) bundle ??= publishedInIndex(bundleIndex);
	return publishedWith(bundle, names);
}
