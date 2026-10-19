import { noStore, type Route } from "@mod/http";
import type { Clock, ReadinessReport } from "@mod/kernel";
import { type Gauge, gauge } from "@mod/metrics";

/** How long an unready report serves later callers, counted from when its run started. */
const reuseMs = 1000;

export type SharedReadiness = () => Promise<ReadinessReport>;

/** One readiness run shared by `/readyz` and the dependency gauge: joined in flight, unready reused. */
export function sharedReadiness(
	report: (deadlineMs: number) => Promise<ReadinessReport>,
	deadlineMs: number,
	clock: Clock,
): SharedReadiness {
	let last:
		| {
				readonly started: number;
				readonly report: Promise<ReadinessReport>;
				settled?: "ready" | "unready";
		  }
		| undefined;
	return () => {
		const now = clock.now();
		const fresh = (started: number) => now >= started && now - started < reuseMs;
		// Ready is never reused, so a failure or a stop shows at once; a clock set back runs anew.
		if (last && (!last.settled || (last.settled === "unready" && fresh(last.started)))) {
			return last.report;
		}
		const run: NonNullable<typeof last> = { started: now, report: report(deadlineMs) };
		run.report.then(
			({ answer }) => {
				run.settled = answer;
			},
			() => {
				run.settled = "unready";
			},
		);
		last = run;
		return run.report;
	};
}

/** `GET /readyz`: the shared run's answer, never which probe failed. */
export function readyz(shared: SharedReadiness): Route {
	return {
		method: "GET",
		changesState: false,
		path: "/readyz",
		takes: ["none"],
		handle: async () => {
			const { answer } = await shared();
			return {
				status: answer === "ready" ? 200 : 503,
				headers: noStore,
				body: { json: { status: answer } },
			};
		},
	};
}

/** `auth_dependency_up`, as legacy names it: 1 or 0 per probe, from the shared run at each sample. */
export function dependencyUp(names: readonly string[], shared: SharedReadiness): Gauge {
	const spec = {
		name: "auth_dependency_up",
		help: "1 when a backing dependency answered its readiness probe, 0 otherwise.",
	};
	// A label needs one value at least; with no probes the gauge has no label and no series.
	if (names.length === 0) return gauge({ ...spec, labels: {} }, () => []);
	return gauge({ ...spec, labels: { dependency: names } }, async () =>
		(await shared()).probes.map((probe) => ({
			labels: { dependency: probe.name },
			value: probe.up ? 1 : 0,
		})),
	);
}
