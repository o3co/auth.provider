import type { Log } from "@mod/kernel";
import type { AuthContext, LoginFacts } from "@mod/session";

const namedTimes: readonly string[] = ["opening", "unknown"];

export function checkAuthenticatedAt(facts: LoginFacts): void {
	const at = facts.authenticatedAt;
	const held =
		typeof at === "number"
			? Number.isFinite(at) && at >= 0 && at <= 8.64e15
			: namedTimes.includes(at);
	if (!held)
		throw new TypeError('authenticatedAt must be epoch milliseconds, "opening" or "unknown"');
}

/** The authentication time a session keeps from its login: the opening where it names it, else the one reported, at most the opening. */
export function authenticatedAtOf(
	facts: LoginFacts,
	openedAt: number,
	log: Log,
): Pick<AuthContext, "authenticatedAt" | "authenticatedAtUnknown"> {
	const reported = facts.authenticatedAt;
	if (reported === "unknown") return { authenticatedAt: openedAt, authenticatedAtUnknown: true };
	if (typeof reported !== "number") return { authenticatedAt: openedAt };
	if (reported > openedAt) log.warn("session-lifecycle.authentication_time_capped");
	return { authenticatedAt: Math.min(reported, openedAt) };
}
