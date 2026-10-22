/** What a plan is composed by and from: the release alone, or the release and packages outside it. */
import { existsSync, readFileSync } from "node:fs";
import { appZod, type Packages } from "@mod/app-output";
import {
	addable,
	type Combinations,
	combinationsWith,
	completed,
	composed,
	full,
	needed,
	optIns,
} from "@mod/combinations";
import { readOutside } from "./outside/contract.ts";
import { bundleIndex, type Indexed, packagesFor, publishedIn } from "./packages.ts";

/** The packages outside the release a plan composes: where pnpm installed them, and those let through though fresh. */
export interface OutsidePlan {
	/** The project the operator had pnpm install them into. */
	readonly from: string;
	readonly names: readonly string[];
	readonly fresh?: readonly string[];
}

export interface Assembly {
	readonly packages: Packages;
	readonly combinations: Combinations;
}

const release: Combinations = { completed, composed, full, optIns, addable, needed };

/**
 * How a plan is composed and where its packages come from. With packages outside the release, they
 * are read from the project named, beside the published release alone: never with a workspace
 * linked, nor from the workspace itself, where nothing is published.
 */
export function assemblyFor(
	plan: { readonly workspace?: string; readonly outside?: OutsidePlan },
	index = bundleIndex,
): Assembly {
	if (plan.outside === undefined)
		return { packages: packagesFor(plan, index), combinations: release };
	if (plan.workspace !== undefined) {
		throw new Error(
			"a linked workspace composes no package outside the release: its packages are not the published ones",
		);
	}
	if (!existsSync(index))
		throw new Error("packages outside the release are composed beside the published release alone");
	const indexed = JSON.parse(readFileSync(index, "utf8")) as Indexed;
	const bundles = new Map(indexed.packages.map((entry) => [entry.name, entry.package]));
	const read = readOutside(plan.outside.from, plan.outside.names, {
		version: indexed.version,
		zod: appZod,
		bundleOf: (module) => bundles.get(module),
	});
	return {
		packages: publishedIn(indexed, {
			read,
			...(plan.outside.fresh ? { fresh: plan.outside.fresh } : {}),
		}),
		combinations: combinationsWith(read.outside.map((o) => o.declaration)),
	};
}
