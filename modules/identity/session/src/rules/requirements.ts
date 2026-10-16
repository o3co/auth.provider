import type { AuthContext, EntryLevel, EntryRequirement } from "../contract.ts";

/** Asks the requirements in name order; the first that falls short is the answer. */
export function firstShortOf(given: readonly EntryRequirement[]) {
	// Names are unique keys, so no two compare equal.
	const requirements = given.toSorted((a, b) => (a.name < b.name ? -1 : 1));
	return async (context: AuthContext, level: EntryLevel) => {
		for (const requirement of requirements) {
			const judged = await requirement.admits(context, level);
			if (judged.kind === "short") return { requirement: requirement.name, answer: judged.answer };
		}
		return undefined;
	};
}

/** The seconds a sign-in stays recent enough to change credentials where no requirement judges that. */
export const credentialsSecondsDefault = 300;

const stepUp = { requirement: "session", answer: { error: "step_up_required" } } as const;

/**
 * Asks the requirements as `firstShortOf` does; then, at `credentials` with none that judges it,
 * needs a sign-in at a known time within `credentialsMs` of `now`.
 */
export function entryShortOf(
	given: readonly EntryRequirement[],
	now: () => number,
	credentialsMs = credentialsSecondsDefault * 1000,
) {
	const shortOf = firstShortOf(given);
	const judged = given.some((r) => r.judges.includes("credentials"));
	return async (context: AuthContext, level: EntryLevel) => {
		const short = await shortOf(context, level);
		if (short || level !== "credentials" || judged) return short;
		const recent =
			!context.authenticatedAtUnknown && now() - context.authenticatedAt <= credentialsMs;
		return recent ? undefined : stepUp;
	};
}
