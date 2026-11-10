import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { defineModule } from "@mod/kernel";
import { httpServers, marks, policies, routes } from "./contract.ts";
import { brokenGuarantees } from "./guarantees/guarantees.ts";
import { withPolicies } from "./guards/guards.ts";
import { drain, serve } from "./serving/server.ts";

export default defineModule(
	{
		name: "http-server",
		// Safe on many instances as http is: what it serves by comes from http's section on each.
		replicaSafe: true,
		takes: [marks, policies, routes],
	},
	(m) => [
		m.contribute(httpServers).by(async (c) => {
			const declared = await c.collect(routes);
			const rules = await c.collect(policies);
			const applied = withPolicies(declared, rules);
			if (applied.kind === "twice") {
				return c.refuse(
					"http-server.policies",
					`more than one rule for a policy: ${applied.label}`,
				);
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
			return {
				serve: async ({ routes: given, settings, ends, log, clock }) => {
					const guarded = withPolicies(given, rules);
					if (guarded.kind !== "applied")
						throw new Error("http-server serves the routes it checked");
					const server = serve({
						routes: guarded.routes,
						proxies: settings.proxies,
						origins: settings.origins,
						ends,
						log,
						clock,
						limits: settings.limits,
					});
					server.listen(settings.port, settings.host);
					await once(server, "listening");
					return {
						port: (server.address() as AddressInfo).port,
						drain: (signal) => drain(server, signal),
					};
				},
			};
		}),
	],
);
