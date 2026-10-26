import type { Expected } from "../expected/expected.ts";
import type { ModuleRun, Outcome } from "../results/results.ts";

/**
 * A plan as it ran: each suite test's outcome, the expected entries no test used, the word of what
 * drove the plan, and where its records are kept.
 */
export interface PlanRun {
	readonly modules: readonly (ModuleRun & { readonly outcome: Outcome })[];
	readonly unused: readonly Expected[];
	/** What drove the plan (the suite's own runner, or the harness), how it ended, and the record of what it said. */
	readonly driver: {
		readonly name: string;
		readonly code: number | null;
		/** Its record's file, under `artifacts`. */
		readonly log: string;
	};
	readonly artifacts: string;
}
