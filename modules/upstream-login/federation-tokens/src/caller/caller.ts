import type { HttpRequest } from "@mod/http";
import type { BuildContext } from "@mod/kernel";
import { type Lineage, lineage } from "@mod/refresh";
import { type SenderBindings, senderBinding } from "@mod/sender-binding";
import { type Sessions, sessions } from "@mod/session";
import { type SessionTokens, sessionTokens } from "@mod/session-tokens";
import { type Tokens, tokens } from "@mod/tokens";

/** The client that presented its access token, and the open session that token was issued in. */
export type Caller =
	| {
			readonly kind: "accepted";
			readonly client: string;
			readonly session: string;
			readonly subject: string;
	  }
	| {
			readonly kind: "refused";
			readonly status: 400 | 401;
			readonly error?: string;
			readonly headers: Readonly<Record<string, string>>;
	  };

export interface Parts {
	readonly senderBinding: SenderBindings;
	readonly tokens: Tokens;
	readonly lineage: Lineage;
	readonly sessionTokens: SessionTokens;
	readonly sessions: Sessions;
}

/**
 * Accepts the access token a request presents: admitted by `sender-binding`, its audience naming
 * the client it was issued to, its family not ended, and issued in a session still open for the
 * same subject. Every refusal past admission is the same `invalid_token`. Throws Unavailable when
 * a check cannot tell.
 */
export function callerWith(parts: Parts) {
	const accepted = async (request: HttpRequest): Promise<Caller> => {
		const admission = await parts.senderBinding.admitted(request, parts.tokens);
		if (admission.kind === "refused") return admission;
		const { id, grant, tokenType } = admission.access;
		const refused: Caller = {
			kind: "refused",
			status: 401,
			error: "invalid_token",
			headers: { "www-authenticate": `${tokenType} error="invalid_token"` },
		};
		if (!grant.audience.includes(grant.issuedTo)) return refused;
		if ((await parts.lineage.of(id)).kind === "ended") return refused;
		const bound = await parts.sessionTokens.sessionOf(id);
		if (bound.kind !== "bound") return refused;
		const open = await parts.sessions.openContext(bound.handle);
		if (open?.subject !== grant.subject) return refused;
		return {
			kind: "accepted",
			client: grant.issuedTo,
			session: bound.handle,
			subject: grant.subject,
		};
	};
	return {
		accepted,
		/** Whether the session is still open for the subject, checked again just before answering. */
		stillOpen: async (caller: Extract<Caller, { kind: "accepted" }>) =>
			(await parts.sessions.openContext(caller.session))?.subject === caller.subject,
	};
}

export type CallerCheck = ReturnType<typeof callerWith>;

/** The check, from the contracts it reads. */
export async function callerFrom(c: Pick<BuildContext<unknown>, "get">): Promise<CallerCheck> {
	return callerWith({
		senderBinding: await c.get(senderBinding),
		tokens: await c.get(tokens),
		lineage: await c.get(lineage),
		sessionTokens: await c.get(sessionTokens),
		sessions: await c.get(sessions),
	});
}
