import type { RequestEndObserver } from "@mod/http";
import { type Histogram, histogram } from "@mod/metrics";

type Label = "method" | "route" | "status";

const METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"];
// 100-599. Node writes up to 999; metrics drops a status above 599, warning once.
const STATUSES = Array.from({ length: 500 }, (_, i) => String(100 + i));
// No route's handler ran: 400, 404, 405 and preflight answers.
const UNMATCHED = "unmatched";
// In seconds: prom-client's default buckets, 5 ms to 10 s.
const LATENCY_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

export type Duration = Histogram<Label>;

/** Labels come from http's own decisions: the routes' declared paths, never a request's path. */
export function requestDuration(paths: readonly string[]): Duration {
	return histogram({
		name: "http_request_duration_seconds",
		help: "HTTP request latency in seconds, by method, route and status.",
		labels: {
			method: [...METHODS, "other"],
			route: [...new Set([...paths, UNMATCHED])],
			status: STATUSES,
		},
		buckets: LATENCY_BUCKETS,
	});
}

/** Counts each request's end once by method, the declared route reached and the status written. */
export function timing(duration: Duration): RequestEndObserver {
	return {
		ended: ({ method, route, status, ms }) => {
			// 499: the client closed before any answer was written.
			const written = status === "closed" ? "499" : String(status);
			const known = METHODS.find((m) => m === method) ?? "other";
			duration.observe({ method: known, route: route ?? UNMATCHED, status: written }, ms / 1000);
		},
	};
}
