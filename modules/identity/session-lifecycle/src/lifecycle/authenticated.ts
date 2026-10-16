import type { Log } from "@mod/kernel";
import type { AuthContext, LoginFacts } from "@mod/session";

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
