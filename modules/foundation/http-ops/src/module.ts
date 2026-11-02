import { requestEnds, routes } from "@mod/http";
import { contract, defineModule, probes } from "@mod/kernel";
import { instruments } from "@mod/metrics";
import { liveness } from "./liveness.ts";
import { dependencyUp, readyz, type SharedReadiness, sharedReadiness } from "./readiness.ts";
import { section } from "./section.ts";
import { type Duration, requestDuration, timing } from "./timing.ts";

/** The request-duration histogram, labelled by the declared paths of every route. */
const duration = contract<Duration>("http-ops.request-duration");

/** The readiness run `/readyz` and the dependency gauge share, one per assembly. */
const readiness = contract<SharedReadiness>("http-ops.shared-readiness");

export default defineModule(
	// Safe on many instances: readiness and the request histogram are each instance's own, as they should be.
	{ name: "http-ops", replicaSafe: true, section, takes: [routes, probes] },
	(m) => [
		m
			.provide(readiness)
			.by((c) =>
				sharedReadiness((ms) => c.readinessReport(ms), c.section["readiness-deadline"], c.clock),
			),
		m.contribute(routes).by(async (c) => readyz(await c.get(readiness))),
		m.contribute(instruments).by(async (c) =>
			dependencyUp(
				(await c.collect(probes)).map((probe) => probe.name),
				await c.get(readiness),
			),
		),
		m.contribute(routes).by(() => liveness()),
		m
			.provide(duration)
			.by(async (c) => requestDuration((await c.collect(routes)).map((route) => route.path))),
		m.contribute(instruments).by((c) => c.get(duration)),
		m.contribute(requestEnds).by(async (c) => timing(await c.get(duration))),
	],
);
