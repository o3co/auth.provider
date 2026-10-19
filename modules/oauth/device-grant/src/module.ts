import { csrfChecked } from "@mod/csrf";
import { grants, sessionIssuances } from "@mod/grants";
import { routes, site, use } from "@mod/http";
import { metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { requestsPerSource } from "@mod/rate-limit";
import { authorizationOver } from "./authorization/authorization.ts";
import { grantOver } from "./grant/grant.ts";
import { section } from "./section.ts";
import { verificationOver } from "./verification/verification.ts";

export const authorizationPath = "/oauth/device_authorization";
export const verificationPath = "/oauth/device/verification";

export default defineModule({ name: "device-grant", section }, (m) => [
	m.contribute(routes).by(async (c) => {
		const window = { limit: c.section.requests, ms: c.section.window * 1000 };
		return {
			method: "POST",
			path: authorizationPath,
			uses: [use(requestsPerSource, { name: "device-grant.authorization", window })],
			crossSite:
				"A device's client calls it with its own client authentication and reads no cookie.",
			...(await authorizationOver(c)),
		};
	}),
	m.contribute(routes).by(async (c) => ({
		method: "POST",
		path: verificationPath,
		takes: ["json"],
		uses: [use(csrfChecked)],
		unlimited:
			"Every action counts against the subject in rate-limit's attempt limit, in the handler.",
		...(await verificationOver(c)),
	})),
	m.contribute(metadata).by(async (c) => {
		const { origin } = await c.get(site);
		return {
			name: "device_authorization_endpoint",
			value: origin === undefined ? undefined : new URL(authorizationPath, origin).href,
		};
	}),
	m.contribute(grants).by(async (c) => {
		// Its tokens are bound to the session that approved them: unrecorded, a logout could not end them.
		if ((await c.collect(sessionIssuances)).length === 0) {
			return c.refuse(
				"device-grant",
				"its tokens must be recorded to the session that approved them, so that a logout ends them",
			);
		}
		return grantOver(c);
	}),
]);
