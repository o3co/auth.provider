import { type HttpRequest, type HttpResponse, noStore, type Route } from "@mod/http";
import type { Factors } from "@mod/mfa";
import type { Sessions } from "@mod/session";

export interface HandlerParts {
	readonly factors: Factors;
	readonly sessions: Sessions;
}

type Handler = Route["handle"];

export const answer = (status: number, json: unknown): HttpResponse => ({
	status,
	headers: noStore,
	body: { json },
});
const loginRequired = answer(401, { error: "login_required" });
const unknownFactor = answer(404, { error: "unknown_factor" });
/** `mfa`'s refusal of a label (`malformed-label`), in the routes' words. */
const invalidLabel = answer(400, { error: "invalid_request", error_description: "invalid label" });

/** The session entered at the credential-changing level, or the answer refusing it. */
const managing = async (sessions: Sessions, request: HttpRequest) => {
	const entry = await sessions.enterFor(request, "credentials");
	if (entry.kind === "entered") return entry.session;
	return entry.kind === "absent" ? loginRequired : answer(403, entry.answer);
};

export function handlersOver(p: HandlerParts) {
	const list: Handler = async (request) => {
		const session = await p.sessions.enter(request);
		if (!session) return loginRequired;
		return answer(200, { factors: await p.factors.held(session.context.subject) });
	};

	const rename: Handler = async (request) => {
		const session = await managing(p.sessions, request);
		if ("status" in session) return session;
		const renamed = await p.factors.rename(
			session.context.subject,
			request.fields.single("factor_id") ?? "",
			request.fields.single("label") ?? "",
		);
		if (renamed === "malformed-label") return invalidLabel;
		return renamed === "renamed" ? answer(200, {}) : unknownFactor;
	};

	const remove: Handler = async (request) => {
		const session = await managing(p.sessions, request);
		if ("status" in session) return session;
		const removed = await p.factors.remove(
			session.context.subject,
			request.fields.single("factor_id") ?? "",
		);
		if (removed === "last") return answer(409, { error: "mfa_last_factor" });
		return removed === "removed" ? answer(200, {}) : unknownFactor;
	};

	const regenerate: Handler = async (request) => {
		const session = await managing(p.sessions, request);
		if ("status" in session) return session;
		const reissued = await p.factors.reissue(session.context.subject);
		if (reissued.kind === "reissued") return answer(200, { recovery_codes: reissued.codes });
		return reissued.kind === "no-qualifying-factor"
			? answer(409, { error: "mfa_no_qualifying_factor" })
			: answer(404, { error: "unknown_kind" });
	};

	return { list, rename, remove, regenerate };
}
