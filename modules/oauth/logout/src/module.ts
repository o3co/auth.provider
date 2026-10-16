import { audit, declaredAudit } from "@mod/audit";
import { csrfChecked } from "@mod/csrf";
import { type HttpRequest, type HttpResponse, noStore, routes, use } from "@mod/http";
import { defineModule, isUnavailable } from "@mod/kernel";
import { determinedSource } from "@mod/request-source";
import { sessions } from "@mod/session";
import events from "./audit-events.ts";

const answer = (status: number, json: unknown, cookies: readonly string[] = []): HttpResponse => ({
	status,
	headers: noStore,
	body: { json },
	...(cookies.length > 0 ? { cookies } : {}),
});

export default defineModule({ name: "logout" }, (m) => [
	m.contribute(routes).by(async (c) => {
		const opened = await c.get(sessions);
		const recorded = declaredAudit(await c.get(audit), events);
		const logout = async (request: HttpRequest): Promise<HttpResponse> => {
			const closed = await opened.closeRequest(request);
			const source = determinedSource(request);
			const attributes = {
				...(source === undefined ? {} : { source }),
				...(closed.session ? { sid: closed.session.id } : {}),
			};
			recorded.record(closed.kind === "closed" ? "logout.succeeded" : "logout.close_pending", {
				...(closed.session ? { subject: closed.session.subject } : {}),
				...(Object.keys(attributes).length > 0 ? { attributes } : {}),
			});
			// Pending means a participant has not finished; the session already lets nobody in.
			return closed.kind === "closed"
				? answer(200, {}, closed.cookies)
				: answer(503, { error: "temporarily_unavailable" }, closed.cookies);
		};
		return {
			method: "POST",
			path: "/session/logout",
			takes: ["form", "json", "none"],
			uses: [use(csrfChecked)],
			handle: async (request) => {
				try {
					return await logout(request);
				} catch (error) {
					if (isUnavailable(error)) return answer(503, { error: "temporarily_unavailable" });
					throw error;
				}
			},
		};
	}),
]);
