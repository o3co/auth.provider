import { metadataSections } from "@mod/clients";
import { routes, use } from "@mod/http";
import { metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { returnPaths } from "@mod/login-gates";
import { requestsPerSource } from "@mod/rate-limit";
import { redirects } from "./contract.ts";
import { endpointOver, path, routeOver } from "./route/route.ts";
import { section } from "./section.ts";

export default defineModule({ name: "authorize", section }, (m) => [
	m.contribute(metadataSections).by(() => redirects),
	m.contribute(returnPaths).by(() => ({ path })),
	m.contribute(metadata).by(async (c) => ({
		name: "authorization_endpoint",
		value: await endpointOver(c),
	})),
	// Only the code flow, and PKCE only by S256 (the endpoint refuses anything else).
	m.contribute(metadata).by(() => ({ name: "response_types_supported", value: ["code"] })),
	m.contribute(metadata).by(() => ({ name: "code_challenge_methods_supported", value: ["S256"] })),
	// Answers only in the query, and takes no request object by reference (discovery's default is true).
	m.contribute(metadata).by(() => ({ name: "response_modes_supported", value: ["query"] })),
	m.contribute(metadata).by(() => ({ name: "request_uri_parameter_supported", value: false })),
	...(["GET", "POST"] as const).map((method) =>
		m.contribute(routes).by(async (c) => {
			const window = { limit: c.section.requests, ms: c.section.window * 1000 };
			return {
				method,
				path,
				uses: [use(requestsPerSource, { name: "authorize", window })],
				handle: await routeOver(c),
			};
		}),
	),
]);
