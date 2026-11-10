import { certificateForwarding } from "@mod/client-certificate";
import { defineModule } from "@mod/kernel";
import { proxiesOf } from "@mod/request-source";
import {
	type HttpServer,
	httpServers,
	listening,
	type RunningServer,
	requestEnds,
	routes,
	type ServerInput,
	site,
} from "./contract.ts";
import { section } from "./settings/section.ts";

export default defineModule(
	{
		name: "http",
		// Safe on many instances given the same `public-origin` and `trusted-proxies` on each
		// (deployment-guarantees, Several instances); connection and time limits hold per instance.
		replicaSafe: true,
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
		takes: [httpServers, requestEnds, routes],
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
			// The kernel holds the point to exactly one server.
			const [server] = (await c.collect(httpServers)) as [HttpServer];
			const certificate = c.section["client-certificate"];
			const input: ServerInput = {
				routes: await c.collect(routes),
				settings: {
					host: c.section.host,
					port: c.section.port,
					proxies: proxiesOf(c.section, certificate),
					origins: new Set(c.section["cors-origins"]),
					limits: {
						headersMs: c.section["headers-timeout"] * 1000,
						requestMs: c.section["request-timeout"] * 1000,
						connections: c.section["max-connections"],
					},
				},
				ends: await c.collect(requestEnds),
				log: c.log,
				clock: c.clock,
			};
			let running: RunningServer | undefined;
			c.onStart(async () => {
				running = await server.serve(input);
				c.log.info("http.listening", { port: running.port });
			});
			c.onStop(async (signal) => running?.drain(signal));
			return {
				port: () => {
					if (!running) throw new Error("http is not listening yet");
					return running.port;
				},
			};
		}),
	],
);
