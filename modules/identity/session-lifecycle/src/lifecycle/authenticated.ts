import type { Log } from "@mod/kernel";
import type { AuthContext, LoginFacts } from "@mod/session";

export function checkAuthenticatedAt(facts: LoginFacts): void {
	const at = facts.authenticatedAt;
	if (at !== "unknown" && !(Number.isFinite(at) && at >= 0 && at <= 8.64e15))
		throw new TypeError('authenticatedAt must be epoch milliseconds or "unknown"');
}

/** The authentication time a session keeps from its login: the one reported, at most the opening. */
export function authenticatedAtOf(
	facts: LoginFacts,
	openedAt: number,
	log: Log,
): Pick<AuthContext, "authenticatedAt" | "authenticatedAtUnknown"> {
	const reported = facts.authenticatedAt;
	if (reported === "unknown") return { authenticatedAt: openedAt, authenticatedAtUnknown: true };
	if (reported > openedAt) log.warn("session-lifecycle.authentication_time_capped");
	return { authenticatedAt: Math.min(reported, openedAt) };
}
