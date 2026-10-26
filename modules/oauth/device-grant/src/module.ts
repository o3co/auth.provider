import { csrfChecked } from "@mod/csrf";
import { grants, sessionIssuances } from "@mod/grants";
import { routes, use } from "@mod/http";
import { endpointOrigin, issuer, metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { requestsPerSource } from "@mod/rate-limit";
import { authorizationOver, authorizationTakes } from "./authorization/authorization.ts";
import { grantOver, grantTakes } from "./grant/grant.ts";
import { section } from "./section.ts";
import { verificationOver, verificationTakes } from "./verification/verification.ts";

export const authorizationPath = "/oauth/device_authorization";
export const verificationPath = "/oauth/device/verification";

const takes = [...authorizationTakes, ...verificationTakes, ...grantTakes, sessionIssuances];

export default defineModule({ name: "device-grant", section, takes }, (m) => [
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
	m.contribute(metadata).by(async (c) => ({
		name: "device_authorization_endpoint",
		value: new URL(authorizationPath, endpointOrigin(await c.get(issuer))).href,
	})),
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
