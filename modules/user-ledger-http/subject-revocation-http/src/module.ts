import { audit } from "@mod/audit";
import { routes, site } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { attemptLimit, rateLimit } from "@mod/rate-limit";
import { addressesOf } from "@mod/request-source";
import { revocations } from "@mod/subject-revocation";
import { endpointOf } from "./endpoint.ts";
import { section } from "./section.ts";

export default defineModule(
	{
		name: "subject-revocation-http",
		section,
		replicaSafe: true,
		takes: [audit, site, rateLimit, attemptLimit, revocations],
	},
	(m) => [
		m.contribute(routes).by(async (c) => {
			// With no proxy trusted, no request is ever told as https, so every one would be refused.
			if (!(await c.get(site)).proxied) {
				return c.refuse(
					"subject-revocation-http",
					"http trusts no proxy, so no request can be told as https: name the proxy in http's trusted-proxies",
				);
			}
			const { credential, "previous-credential": previous } = c.section;
			return {
				method: "POST",
				path: "/ledger/subject-revocations",
				takes: ["json"],
				crossSite: "A server's call proved by its own credential; it reads no cookie.",
				unlimited:
					"It checks the source and the credential first, then counts failures and authenticated requests apart, per source, in the handler.",
				handle: endpointOf({
					credentials: previous === undefined ? [credential] : [credential, previous],
					sources: addressesOf(c.section.sources),
					failures: {
						limit: await c.get(attemptLimit),
						window: { limit: c.section.failures, ms: c.section["failure-window"] },
					},
					requests: {
						limit: await c.get(rateLimit),
						window: { limit: c.section.requests, ms: c.section.window },
					},
					revocations: await c.get(revocations),
					recorded: await c.get(audit),
					log: c.log,
				}),
			};
		}),
	],
);
