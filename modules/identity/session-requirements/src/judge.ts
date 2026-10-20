import type { EntryJudge, EntryLevel } from "@mod/session";
import type { EntryRequirement } from "./contract.ts";

/** Asks the requirements in name order; the first that falls short is the answer, else admitted with whether one judged the level. */
export function judgeOf(given: readonly EntryRequirement[]): EntryJudge {
	// Names are unique keys, so no two compare equal.
	const requirements = given.toSorted((a, b) => (a.name < b.name ? -1 : 1));
	const judging = (level: EntryLevel) => requirements.some((r) => r.judges.includes(level));
	return {
		judge: async (context, level) => {
			for (const requirement of requirements) {
				const judged = await requirement.admits(context, level);
				if (judged.kind === "short") {
					return { kind: "short", requirement: requirement.name, answer: judged.answer };
				}
			}
			return { kind: "admit", judged: judging(level) };
		},
	};
}
