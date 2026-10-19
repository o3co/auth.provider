import { type HttpRequest, jsonAnswer, type Route } from "@mod/http";
import type { Factors } from "@mod/mfa";
import type { SecondFactors } from "@mod/mfa-entry";
import { refusedEntry, type Sessions } from "@mod/session";

export interface HandlerParts {
	readonly factors: Factors;
	readonly secondFactors: SecondFactors;
	readonly sessions: Sessions;
}

type Handler = Route["handle"];

const unknownFactor = jsonAnswer(404, { error: "unknown_factor" });
/** `mfa`'s refusal of a label (`malformed-label`), in the routes' words. */
const invalidLabel = jsonAnswer(400, {
	error: "invalid_request",
	error_description: "invalid label",
});

/** The session entered at the credential-changing level, or `session`'s answer refusing it. */
const managing = async (sessions: Sessions, request: HttpRequest) => {
	const entry = await sessions.enterFor(request, "credentials");
	return entry.kind === "entered" ? entry.session : refusedEntry(entry);
};
/** A reset or a revocation since the change was allowed: the session is gone too. */
const loginRequired = refusedEntry({ kind: "absent" });
/** As `session` words a step-up it asks for. */
const stepUpRequired = jsonAnswer(403, { error: "step_up_required" });

export function handlersOver(p: HandlerParts) {
	const list: Handler = async (request) => {
		const session = await p.sessions.enter(request);
		if (!session) return refusedEntry({ kind: "absent" });
		return jsonAnswer(200, { factors: await p.factors.held(session.context.subject) });
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
		return renamed === "renamed" ? jsonAnswer(200, {}) : unknownFactor;
	};

	/** Entered at the credential-changing level with a second factor proven recently: what a factor holds goes only to its proof, never to a sign-in judged before a factor was bound. */
	const proving = async (request: HttpRequest) => {
		const session = await managing(p.sessions, request);
		if ("status" in session) return session;
		return p.secondFactors.provenRecently(session.context) ? session : stepUpRequired;
	};

	/** As `proving`, with the subject's fence read in between: a revocation complete after that check fences the change. */
	const fenced = async (request: HttpRequest) => {
		const session = await proving(request);
		if ("status" in session) return session;
		const fence = await p.factors.fenceOf(session.context.subject);
		const still = await proving(request);
		return "status" in still ? still : { session: still, fence };
	};

	const remove: Handler = async (request) => {
		const allowed = await fenced(request);
		if ("status" in allowed) return allowed;
		const removed = await p.factors.remove(
			allowed.session.context.subject,
			request.fields.single("factor_id") ?? "",
			allowed.fence,
		);
		if (removed === "fenced") return loginRequired;
		if (removed === "last") return jsonAnswer(409, { error: "mfa_last_factor" });
		return removed === "removed" ? jsonAnswer(200, {}) : unknownFactor;
	};

	const regenerate: Handler = async (request) => {
		const allowed = await fenced(request);
		if ("status" in allowed) return allowed;
		const reissued = await p.factors.reissue(allowed.session.context.subject, allowed.fence);
		if (reissued.kind === "fenced") return loginRequired;
		if (reissued.kind === "reissued") return jsonAnswer(200, { recovery_codes: reissued.codes });
		return reissued.kind === "no-qualifying-factor"
			? jsonAnswer(409, { error: "mfa_no_qualifying_factor" })
			: jsonAnswer(404, { error: "unknown_kind" });
	};

	return { list, rename, remove, regenerate };
}
