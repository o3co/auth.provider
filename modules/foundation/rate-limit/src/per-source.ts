import { type Audit, declaredAudit } from "@mod/audit";
import { applying, type HttpRequest, type HttpResponse, noStore } from "@mod/http";
import { isUnavailable, type Log } from "@mod/kernel";
import { type Counter, counter } from "@mod/metrics";
import { determinedSource } from "@mod/request-source";
import events from "./audit-events.ts";
import { attemptsPerSource, type RateLimit, requestsPerSource, type Window } from "./contract.ts";
import { sourceKey } from "./source.ts";

const unavailable: HttpResponse = {
	status: 503,
	headers: noStore,
	body: { json: { error: "service_unavailable" } },
};

/** The limits a source is counted for, and what an uncounted request was answered. */
export type UncountedLabel = "limit" | "outcome";

/** Requests the store could not count; one is made at each build, and records only once metrics takes it. */
export const uncountedCounter = (): Counter<UncountedLabel> =>
	counter({
		name: "auth_rate_limit_uncounted_total",
		help: "Requests a limit could not count as the store could not tell, by limit and whether they were refused or let through.",
		labels: { limit: ["attempts", "requests"], outcome: ["refused", "let_through"] },
	});

interface Told {
	readonly log: Log;
	readonly recorded: Pick<Audit, "record">;
	readonly uncounted: Counter<UncountedLabel>;
}

interface Counting {
	readonly limit: "attempts" | "requests";
	readonly error: string;
	readonly uncounted: HttpResponse | "pass";
}

/** Counts a route's requests by source; over the limit, `429` with `error`; uncounted, `uncounted`. */
function perSource(
	counting: RateLimit,
	{ log, recorded, uncounted: counted }: Told,
	{ limit, error, uncounted }: Counting,
) {
	return async (request: HttpRequest, { name, window }: { name: string; window: Window }) => {
		const source = determinedSource(request);
		if (source === undefined) {
			log.error("rate-limit.source_undetermined", { proxy: request.source.address });
			return unavailable;
		}
		const hit = await counting.hit(name, sourceKey(source), window).catch((failure) => {
			if (isUnavailable(failure)) return undefined;
			throw failure;
		});
		if (!hit) {
			log.warn("rate-limit.uncounted", { name });
			declaredAudit(recorded, events).record("rate_limit.unavailable", {
				attributes: { name, limit, source },
			});
			counted.add({ limit, outcome: uncounted === "pass" ? "let_through" : "refused" });
			return uncounted;
		}
		if (hit.kind === "allowed") return "pass" as const;
		const seconds = String(Math.ceil(hit.retryAfterMs / 1000));
		return {
			status: 429,
			headers: { ...noStore, "retry-after": seconds },
			body: { json: { error } },
		};
	};
}

export const limitingAttempts = (counting: RateLimit, told: Told) =>
	applying(
		attemptsPerSource,
		perSource(counting, told, {
			limit: "attempts",
			error: "too_many_attempts",
			uncounted: unavailable,
		}),
	);

export type FailMode = "open" | "closed";

export const limitingRequests = (counting: RateLimit, told: Told, failMode: FailMode) =>
	applying(
		requestsPerSource,
		perSource(counting, told, {
			limit: "requests",
			error: "rate_limited",
			uncounted: failMode === "open" ? "pass" : unavailable,
		}),
	);
