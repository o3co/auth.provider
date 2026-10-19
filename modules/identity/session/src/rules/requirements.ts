import type { AuthContext, EntryJudge, EntryLevel, Judgement } from "../contract.ts";

/** The seconds a sign-in stays recent enough to change credentials where no requirement judges that. */
export const credentialsSecondsDefault = 300;

const stepUp = { requirement: "session", answer: { error: "step_up_required" } } as const;

/**
 * The judge's answer; then, at `credentials` where nothing judged it (or no judge is contributed),
 * a sign-in at a known time that `recent` holds recent, else `session` short with `step_up_required`.
 */
export function judgedShortOf(judge: EntryJudge | undefined, recent: (at: number) => boolean) {
	return async (context: AuthContext, level: EntryLevel) => {
		const judged: Judgement = judge
			? await judge.judge(context, level)
			: { kind: "admit", judged: false };
		if (judged.kind === "short") return { requirement: judged.requirement, answer: judged.answer };
		if (level !== "credentials" || judged.judged) return undefined;
		const known = !context.authenticatedAtUnknown && recent(context.authenticatedAt);
		return known ? undefined : stepUp;
	};
}
