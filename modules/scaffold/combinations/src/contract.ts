import { existsSync } from "node:fs";
import { join } from "node:path";
import {
	completedOf,
	composedWith,
	fullWith,
	neededWith,
	optInsOf,
	type Selection,
} from "./composed.ts";
import { type Declared, declaredIn, declaredInIndex } from "./declared.ts";

export type { Selection } from "./composed.ts";
export { type Kind, kinds } from "./kinds.ts";

let workspace: Declared | undefined;

/** The modules given (owners a declared default replaces swapped for it), then their wirings and bridges, each once, first named first. */
export function completed(modules: readonly string[]): string[] {
	return completedOf(declared(), modules);
}

/** Read once: built into a bundle, the index at its root; in the workspace, the workspace itself. */
const declared = () => {
	const index = join(import.meta.dirname, "..", "..", "index.json");
	workspace ??= existsSync(index)
		? declaredInIndex(index)
		: declaredIn(join(import.meta.dirname, "..", "..", "..", ".."));
	return workspace;
};

/** What a selection composes (see `composedWith`); refuses, naming each, what cannot be selected. */
export const composed = (selection: Selection): string[] => composedWith(declared(), selection);

/** The full template: every foundation and feature that does not opt in, with each default, and what is added. */
export const full = (add?: readonly string[]): string[] => fullWith(declared(), add);

/** The features that opt in, which the full template leaves out until added. */
export const optIns = (): string[] => optInsOf(declared());

/** The modules given, what they need to run, then `completed`, as `composed` reaches them but with no axis default. */
export const needed = (modules: readonly string[]): string[] => neededWith(declared(), modules);
