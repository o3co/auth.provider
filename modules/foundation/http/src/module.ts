import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { certificateForwarding } from "@mod/client-certificate";
import { defineModule } from "@mod/kernel";
import { proxiesOf } from "@mod/request-source";
import { listening, marks, policies, requestEnds, routes, site } from "./contract.ts";
import { brokenGuarantees } from "./guarantees/guarantees.ts";
import { withPolicies } from "./guards/guards.ts";
import { drain, serve } from "./serving/server.ts";
import { section } from "./settings/section.ts";

export default defineModule(
	{
		name: "http",
		section,
		// A plain-http origin sends the session's cookie in the clear: for trying it on one machine.
		refusedInProduction: (s) =>
			s["insecure-origin"]
				? [
						{
							key: "insecure-origin",
							reason:
								"takes a plain-http public origin, which a production deployment does not; set kernel.environment = development to try one",
						},
					]
				: [],
		takes: [marks, policies, requestEnds, routes],
	},
	(m) => [
		m.provide(site).by((c) => {
			const origin = c.section["public-origin"];
			return Object.freeze({
				origin,
				secureCookies: !origin?.startsWith("http:"),
				proxied: c.section["trusted-proxies"].length > 0,
			});
		}),
		m
			.provide(certificateForwarding)
			.by((c) => Object.freeze({ configured: c.section["client-certificate"] !== undefined })),
		m.provide(listening).by(async (c) => {
			const declared = await c.collect(routes);
			const applied = withPolicies(declared, await c.collect(policies));
			if (applied.kind === "twice") {
				return c.refuse("http.policies", `more than one rule for a policy: ${applied.label}`);
			}
			if (applied.kind === "missing") {
				return c.refuseAll(
					applied.missing.map(({ route, label }) => ({
						where: `http.routes:${route.method} ${route.path}`,
						reason: `uses a policy no module applies: ${label}`,
					})),
				);
			}
			const broken = brokenGuarantees(declared, await c.collect(marks));
			if (broken.length > 0) {
				return c.refuseAll(
					broken.map(({ route, reason }) => ({
						where: `http.routes:${route.method} ${route.path}`,
						reason,
					})),
				);
			}
			const certificate = c.section["client-certificate"];
			const server = serve({
				routes: applied.routes,
				proxies: proxiesOf(c.section, certificate),
				origins: new Set(c.section["cors-origins"]),
				ends: await c.collect(requestEnds),
				log: c.log,
				clock: c.clock,
				limits: {
					headersMs: c.section["headers-timeout"] * 1000,
					requestMs: c.section["request-timeout"] * 1000,
					connections: c.section["max-connections"],
				},
			});
			const port = () => (server.address() as AddressInfo).port;
			c.onStart(async () => {
				server.listen(c.section.port, c.section.host);
				await once(server, "listening");
				c.log.info("http.listening", { port: port() });
			});
			c.onStop((signal) => drain(server, signal));
			return { port };
		}),
	],
);
