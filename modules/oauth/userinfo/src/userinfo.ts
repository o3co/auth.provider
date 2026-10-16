import { type HttpRequest, type HttpResponse, noStore } from "@mod/http";
import type { ReleasedClaims } from "@mod/oidc";
import { challengeOf, type SenderBindings } from "@mod/sender-binding";
import type { Sessions } from "@mod/session";
import type { SessionTokens } from "@mod/session-tokens";
import type { Tokens } from "@mod/tokens";

export interface UserinfoParts {
	readonly senderBinding: Pick<SenderBindings, "admitted">;
	readonly tokens: Pick<Tokens, "verifyAccess">;
	readonly sessionTokens: Pick<SessionTokens, "sessionOf">;
	readonly sessions: Pick<Sessions, "openContext">;
	readonly claims: Pick<ReleasedClaims, "of">;
}

const answer = (
	status: number,
	json: unknown,
	headers: Record<string, string> = {},
): HttpResponse => ({
	status,
	headers: { ...noStore, ...headers },
	body: { json },
});
/** A check or the claims could not tell: never a refusal, never a claim. */
export const unavailable = answer(503, { error: "temporarily_unavailable" });

/**
 * Answers the subject of the access token the request presents, and the claims oidc releases for its
 * scope while the session it was issued in is open for that subject. Throws Unavailable when a check
 * cannot tell.
 */
export function userinfoOver(p: UserinfoParts) {
	return async (request: HttpRequest): Promise<HttpResponse> => {
		const admission = await p.senderBinding.admitted(request, p.tokens);
		if (admission.kind === "refused") {
			const { status, error, headers } = admission;
			return answer(status, error === undefined ? {} : { error }, headers);
		}
		const { id, grant, tokenType } = admission.access;
		// OIDC Core §5.3 serves a token issued for openid; any other is short of scope (RFC 6750 §3.1).
		if (!grant.scope.includes("openid")) {
			return answer(
				403,
				{ error: "insufficient_scope" },
				challengeOf(tokenType, "insufficient_scope"),
			);
		}
		const bound = await p.sessionTokens.sessionOf(id);
		// A token issued in no session (client credentials, say) is answered its subject only.
		if (bound.kind === "unbound") return answer(200, { sub: grant.subject });
		const context = await p.sessions.openContext(bound.handle);
		if (context?.subject !== grant.subject) {
			// Challenged in the token's own scheme, as sender-binding challenges a token it refuses.
			return answer(401, { error: "invalid_token" }, challengeOf(tokenType, "invalid_token"));
		}
		const claims = await p.claims.of(grant.subject, grant.scope, bound.handle);
		return answer(200, { ...claims, sub: grant.subject });
	};
}
