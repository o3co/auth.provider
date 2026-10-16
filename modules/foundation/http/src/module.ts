import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { certificateForwarding } from "@mod/client-certificate";
import { defineModule } from "@mod/kernel";
import { proxiesOf } from "@mod/request-source";
import { listening, policies, requestEnds, routes, site } from "./contract.ts";
import { withPolicies } from "./guards/guards.ts";
import { drain, serve } from "./serving/server.ts";
import { section } from "./settings/section.ts";

export default defineModule({ name: "http", section }, (m) => [
	m.provide(site).by((c) => {
		const origin = c.section["public-origin"];
		return Object.freeze({ origin, secureCookies: !origin?.startsWith("http:") });
	}),
	m
		.provide(certificateForwarding)
		.by((c) => Object.freeze({ configured: c.section["client-certificate"] !== undefined })),
	m.provide(listening).by(async (c) => {
		const applied = withPolicies(await c.collect(routes), await c.collect(policies));
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
		const certificate = c.section["client-certificate"];
		const server = serve({
			routes: applied.routes,
			proxies: proxiesOf(c.section, certificate),
			origins: new Set(c.section["cors-origins"]),
			ends: await c.collect(requestEnds),
			log: c.log,
			clock: c.clock,
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
]);
