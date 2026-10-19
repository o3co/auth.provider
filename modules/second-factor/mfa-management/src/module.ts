import { csrfChecked } from "@mod/csrf";
import { jsonAnswer, type Route, routes, use } from "@mod/http";
import { defineModule, isUnavailable } from "@mod/kernel";
import { factors } from "@mod/mfa";
import { requestsPerSource } from "@mod/rate-limit";
import { sessions } from "@mod/session";
import { handlersOver } from "./handlers.ts";
import { section } from "./section.ts";

type HandlerName = keyof ReturnType<typeof handlersOver>;

/** The package's routes; every POST checks same-origin, then the requests per source. */
const table = [
	["GET", "/session/mfa/factors", "list"],
	["POST", "/session/mfa/factors/rename", "rename"],
	["POST", "/session/mfa/factors/remove", "remove"],
	["POST", "/session/mfa/recovery-codes", "regenerate"],
] as const satisfies readonly (readonly ["GET" | "POST", string, HandlerName])[];

const unavailable = jsonAnswer(503, { error: "temporarily_unavailable" });

const withUnavailable =
	(handle: Route["handle"]): Route["handle"] =>
	async (request) => {
		try {
			return await handle(request);
		} catch (error) {
			if (isUnavailable(error)) return unavailable;
			throw error;
		}
	};

export default defineModule({ name: "mfa-management", section, replicaSafe: true }, (m) =>
	table.map(([method, path, name]) =>
		m.contribute(routes).by(async (c): Promise<Route> => {
			const handlers = handlersOver({
				factors: await c.get(factors),
				sessions: await c.get(sessions),
			});
			const handle = withUnavailable(handlers[name]);
			if (method === "GET") return { method, path, changesState: false, handle };
			const window = { limit: c.section.requests, ms: c.section.window * 1000 };
			return {
				method,
				path,
				uses: [use(csrfChecked), use(requestsPerSource, { name: "mfa-management", window })],
				takes: ["form", "json"],
				handle,
			};
		}),
	),
);
