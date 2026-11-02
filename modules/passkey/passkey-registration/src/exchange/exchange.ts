import { csrfChecked } from "@mod/csrf";
import { type HttpRequest, type HttpResponse, jsonAnswer, type Route, use } from "@mod/http";
import { isUnavailable } from "@mod/kernel";
import { requestsPerSource, type Window } from "@mod/rate-limit";
import { determinedSource } from "@mod/request-source";
import type { Sessions } from "@mod/session";

/** A route's work once the session is entered: the request, and the session's subject. */
export type Handler = (request: HttpRequest, subject: string) => Promise<HttpResponse>;

/** How the package's routes meet a request, over the sessions and the requests window. */
export interface Exchange {
	/** Enters the session at `credentials`, then hands its subject on. */
	entered(handle: Handler): (request: HttpRequest) => Promise<HttpResponse>;
	/** A POST route at the path: JSON or no body, under `csrf`'s policy and the requests policy. */
	post(path: string, handle: Handler): Route;
}

export function exchangeOver(sessions: Sessions, window: Window): Exchange {
	const entered = (handle: Handler) => async (request: HttpRequest) => {
		try {
			const entry = await sessions.enterFor(request, "credentials");
			if (entry.kind === "absent") return jsonAnswer(401, { error: "unauthorized" });
			if (entry.kind === "short") return jsonAnswer(403, entry.answer);
			return await handle(request, entry.session.context.subject);
		} catch (error) {
			if (isUnavailable(error)) return jsonAnswer(503, { error: "temporarily_unavailable" });
			throw error;
		}
	};
	const post = (path: string, handle: Handler): Route => ({
		method: "POST",
		path,
		uses: [use(csrfChecked), use(requestsPerSource, { name: "passkey-registration", window })],
		takes: ["json", "none"],
		handle: entered(handle),
	});
	return { entered, post };
}

/** What an audit event records of the request: its source, when determined. */
export const sourced = (request: HttpRequest) => {
	const source = determinedSource(request);
	return source === undefined ? {} : { source };
};

/** A body the routes refuse before `passkeys` is asked. */
export const invalid = (description: string) =>
	jsonAnswer(400, { error: "invalid_request", error_description: description });
