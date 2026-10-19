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

	const remove: Handler = async (request) => {
		const session = await proving(request);
		if ("status" in session) return session;
		const removed = await p.factors.remove(
			session.context.subject,
			request.fields.single("factor_id") ?? "",
		);
		if (removed === "last") return jsonAnswer(409, { error: "mfa_last_factor" });
		return removed === "removed" ? jsonAnswer(200, {}) : unknownFactor;
	};

	const regenerate: Handler = async (request) => {
		const session = await proving(request);
		if ("status" in session) return session;
		const reissued = await p.factors.reissue(session.context.subject);
		if (reissued.kind === "reissued") return jsonAnswer(200, { recovery_codes: reissued.codes });
		return reissued.kind === "no-qualifying-factor"
			? jsonAnswer(409, { error: "mfa_no_qualifying_factor" })
			: jsonAnswer(404, { error: "unknown_kind" });
	};

	return { list, rename, remove, regenerate };
}
