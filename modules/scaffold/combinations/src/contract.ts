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
import { type Declaration, declaredWith } from "./outside.ts";
import { type Published, publishedInIndex, publishedWith } from "./published.ts";

export type { Selection } from "./composed.ts";
export { capabilityBlind, type Kind, kindOrder, kinds, mayNeed } from "./kinds.ts";
export type { Declaration } from "./outside.ts";
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

/** What composing offers, over a given set of declarations. */
export interface Combinations {
	readonly completed: typeof completed;
	readonly composed: typeof composed;
	readonly full: typeof full;
	readonly optIns: typeof optIns;
	readonly addable: typeof addable;
	readonly needed: typeof needed;
}

/**
 * The same, over the workspace (or the bundle's index) and the packages declared outside it, each a
 * module beside it; refuses, naming each, what cannot stand beside it (see `declaredWith`).
 */
export function combinationsWith(outside: readonly Declaration[]): Combinations {
	const merged = declaredWith(declared(), outside);
	return {
		completed: (modules) => completedOf(merged, modules),
		composed: (selection) => composedWith(merged, selection),
		full: (add) => fullWith(merged, add),
		optIns: () => optInsOf(merged),
		addable: () => addableOf(merged),
		needed: (modules) => neededWith(merged, modules),
	};
}

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
