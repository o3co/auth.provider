import {
	type Pkg,
	type Rules,
	type Surface,
	scopeOf,
	surfacesOf,
	type Violation,
} from "@mod/guard-imports";
import { budgetMeasures, type Measure } from "./budget/budget.ts";
import { helpersOf } from "./network/network.ts";
import type { Doc } from "./workspace.ts";

export type { Doc, Measure, Pkg, Violation };

/** The configuration: the budget numbers, beside the rules guard-imports reads. */
export interface Budget extends Rules {
	/** The kind of a wire's contract, held to it alone (G33). */
	readonly protocolKind: string;
	readonly readRangeBytes: number;
	readonly sourceLines: number;
	readonly testLines: number;
	readonly contractValues: number;
	readonly commonContractValues: number;
	/** The members of a package's exported interfaces and type aliases, together. */
	readonly contractMembers: number;
	/** The same, for the kinds whose contract other modules are built on. */
	readonly widerContractMembers: number;
	readonly dependencies: number;
	readonly cardLines: number;
	readonly cardBytes: number;
	/** A package that this many packages depend on at run time has its card held to the narrower lines. */
	readonly narrowCardFanIn: number;
	readonly narrowCardLines: number;
	/** Any card item's bytes, a line opening with `- `, nested ones too. */
	readonly cardItemBytes: number;
	/** The test tables that count as test lines all the same: fixtures. */
	readonly countedFixtureFile: string;
	/** The bytes of the cards of the packages a unit's shipped code imports, together, past which it is reported. */
	readonly dependencyCardBytes: number;
	/**
	 * Comment lines, but for the doc comments of the package's public surface, may reach this share
	 * of the source lines, or the floor, whichever is more.
	 */
	readonly commentShare: number;
	readonly commentFloor: number;
	/** How many consecutive values of a configuration list a document may lay out in order. */
	readonly laidOutValues: number;
	/** Test tables (fixtures, vectors): data for tests, not counted as test lines. */
	readonly fixtureFile: string;
	/** Files a tool writes from another (a bundle): no one reads them as written, so neither their bytes nor their lines count. */
	readonly generatedFile: string;
}

/** Every unit's budget measures, each with its limit where G7 holds one, whether past it or not; on the surfaces given, read once by the caller, or read here. */
export function measures(
	packages: readonly Pkg[],
	budget: Budget,
	surfaces: ReadonlyMap<string, Surface> = surfacesOf(packages),
): Measure[] {
	const s = scopeOf(packages, budget, () => {}, helpersOf(packages));
	return packages.flatMap((p) => budgetMeasures(s, p, surfaces));
}
