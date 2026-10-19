import type { HttpRequest } from "@mod/http";
import type { BuildContext } from "@mod/kernel";
import { type SenderBindings, senderBinding } from "@mod/sender-binding";
import { type Sessions, sessions } from "@mod/session";
import { type SessionTokens, sessionTokens } from "@mod/session-tokens";
import { type Tokens, tokens } from "@mod/tokens";

/** The client that presented its access token, and the entered session it was issued in. */
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
	readonly sessionTokens: SessionTokens;
	readonly sessions: Sessions;
}

/**
 * Accepts the access token a request presents: admitted by `sender-binding` (through `tokens`,
 * every access condition holding, its family's among them), its audience naming the client it was
 * issued to, and issued in a session that enters at use for the same subject. Every refusal past
 * admission is the same `invalid_token`, a session short of a requirement's too. Throws Unavailable
 * when a check cannot tell.
 */
export function callerWith(parts: Parts) {
	/** Whether the session enters at use for the subject; absent or short, it does not. */
	const enters = async (session: string, subject: string) => {
		const entry = await parts.sessions.entryOf(session);
		return entry.kind === "entered" && entry.session.context.subject === subject;
	};
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
		const bound = await parts.sessionTokens.sessionOf(id);
		if (bound.kind !== "bound") return refused;
		if (!(await enters(bound.handle, grant.subject))) return refused;
		return {
			kind: "accepted",
			client: grant.issuedTo,
			session: bound.handle,
			subject: grant.subject,
		};
	};
	return {
		accepted,
		/** Whether the session still enters at use for the subject, checked again before answering. */
		stillEnters: (caller: Extract<Caller, { kind: "accepted" }>) =>
			enters(caller.session, caller.subject),
	};
}

export type CallerCheck = ReturnType<typeof callerWith>;

/** The check, from the contracts it reads. */
export async function callerFrom(c: Pick<BuildContext<unknown>, "get">): Promise<CallerCheck> {
	return callerWith({
		senderBinding: await c.get(senderBinding),
		tokens: await c.get(tokens),
		sessionTokens: await c.get(sessionTokens),
		sessions: await c.get(sessions),
	});
}
