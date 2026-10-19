import { extensionPoint } from "@mod/kernel";
import type { Answer, AuthContext, EntryLevel } from "@mod/session";

/** What a session must meet to be entered at a level, contributed by the module that owns the rule. */
export interface EntryRequirement {
	readonly name: string;
	/** The levels it judges; where none judges `credentials`, `session`'s floor does. */
	readonly judges: readonly EntryLevel[];
	admits(
		context: AuthContext,
		level: EntryLevel,
	): Promise<{ readonly kind: "admit" } | { readonly kind: "short"; readonly answer: Answer }>;
}

export const entryRequirements = extensionPoint<EntryRequirement>(
	"session-requirements.entry-requirements",
	{ multiplicity: "keyed", keyOf: (requirement) => requirement.name },
);
