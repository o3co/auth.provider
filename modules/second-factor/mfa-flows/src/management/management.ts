import type { Factors } from "@mod/mfa";
import type { Sessions } from "@mod/session";
import { answer, field, type Handler, invalidLabel, loginRequired, managing } from "../routing.ts";

export interface ManagementParts {
	readonly factors: Factors;
	readonly sessions: Sessions;
}

const unknownFactor = answer(404, { error: "unknown_factor" });

export function managementOver(p: ManagementParts) {
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
			field(request, "factor_id") ?? "",
			field(request, "label") ?? "",
		);
		if (renamed === "malformed-label") return invalidLabel;
		return renamed === "renamed" ? answer(200, {}) : unknownFactor;
	};

	const remove: Handler = async (request) => {
		const session = await managing(p.sessions, request);
		if ("status" in session) return session;
		const removed = await p.factors.remove(
			session.context.subject,
			field(request, "factor_id") ?? "",
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
