import type { BuildContext } from "@mod/kernel";
import { hintReaders } from "../contract.ts";
import type { Decision } from "../decision.ts";

/** The End-User an `id_token_hint` names, none where none is given or none is read, or the refusal to give. */
export type HintCheck = (
	hint: string | undefined,
) => Promise<
	{ readonly kind: "hint"; readonly subject?: string } | Extract<Decision, { kind: "refuse" }>
>;

/** What `hintCheckOver` takes. */
export const hintCheckTakes = [hintReaders];

/**
 * The hint check over the one reader contributed. With none, no ID token is issued that a hint could
 * be, and a hint is a parameter not understood, so it is left unread (RFC 6749 §3.1).
 */
export async function hintCheckOver(c: Pick<BuildContext<unknown>, "collect">): Promise<HintCheck> {
	const [reader] = await c.collect(hintReaders);
	return async (hint) => {
		if (!hint || !reader) return { kind: "hint" };
		const read = await reader.read(hint);
		if (read.kind !== "subject") {
			return {
				kind: "refuse",
				error: "invalid_request",
				description: "id_token_hint is not valid",
			};
		}
		return { kind: "hint", subject: read.subject };
	};
}
