import { audit, declaredAudit } from "@mod/audit";
import { csrfChecked } from "@mod/csrf";
import { type HttpRequest, type HttpResponse, jsonAnswer, routes, use } from "@mod/http";
import { defineModule, isUnavailable } from "@mod/kernel";
import { determinedSource } from "@mod/request-source";
import { sessions } from "@mod/session";
import events from "./audit-events.ts";

export default defineModule(
	{ name: "logout", replicaSafe: true, takes: [sessions, audit] },
	(m) => [
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
					? jsonAnswer(200, {}, { cookies: closed.cookies })
					: jsonAnswer(503, { error: "temporarily_unavailable" }, { cookies: closed.cookies });
			};
			return {
				method: "POST",
				path: "/session/logout",
				takes: ["form", "json", "none"],
				uses: [use(csrfChecked)],
				unlimited:
					"It closes only the requester's own session; there is nothing to guess or spend.",
				handle: async (request) => {
					try {
						return await logout(request);
					} catch (error) {
						if (isUnavailable(error)) return jsonAnswer(503, { error: "temporarily_unavailable" });
						throw error;
					}
				},
			};
		}),
	],
);
