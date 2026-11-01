import type { AuthContext, LoginFacts } from "../contract.ts";

const namedTimes: readonly string[] = ["opening", "unknown"];
/** The latest time ECMAScript holds, in epoch milliseconds (8.64e15, a hundred million days). */
const latestEpochMs = 8.64e15;

/** A `TypeError`, naming no value, for an authentication time neither epoch milliseconds, `opening` nor `unknown`. */
export function checkAuthenticatedAt(facts: LoginFacts): void {
	const at = facts.authenticatedAt;
	const held =
		typeof at === "number"
			? Number.isFinite(at) && at >= 0 && at <= latestEpochMs
			: namedTimes.includes(at);
	if (!held)
		throw new TypeError('authenticatedAt must be epoch milliseconds, "opening" or "unknown"');
}

/** A `TypeError`, naming no value, for a proof's start given that is not epoch milliseconds. */
export function checkProvenSince(facts: LoginFacts): void {
	const since: unknown = facts.provenSince;
	if (since === undefined) return;
	const held =
		typeof since === "number" && Number.isFinite(since) && since >= 0 && since <= latestEpochMs;
	if (!held) throw new TypeError("provenSince must be epoch milliseconds");
}

/** The authentication time a session keeps from its login, telling `capped` where it took the opening for a later one. */
export function authenticatedAtOf(
	facts: LoginFacts,
	openedAt: number,
	capped: () => void,
): Pick<AuthContext, "authenticatedAt" | "authenticatedAtUnknown"> {
	const reported = facts.authenticatedAt;
	if (reported === "unknown") return { authenticatedAt: openedAt, authenticatedAtUnknown: true };
	if (reported === "opening") return { authenticatedAt: openedAt };
	if (reported > openedAt) capped();
	return { authenticatedAt: Math.min(reported, openedAt) };
}
