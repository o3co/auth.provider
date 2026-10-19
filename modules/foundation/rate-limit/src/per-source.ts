import { type Audit, declaredAudit } from "@mod/audit";
import { applying, type HttpRequest, type HttpResponse, jsonAnswer, type Mark } from "@mod/http";
import { isUnavailable, type Log } from "@mod/kernel";
import { determinedSource } from "@mod/request-source";
import events from "./audit-events.ts";
import { attemptsPerSource, type RateLimit, requestsPerSource, type Window } from "./contract.ts";
import { sourceKey } from "./source.ts";

const unavailable: HttpResponse = jsonAnswer(503, { error: "service_unavailable" });

interface Told {
	readonly log: Log;
	readonly recorded: Pick<Audit, "record">;
}

interface Counting {
	readonly limit: "attempts" | "requests";
	readonly error: string;
	readonly uncounted: HttpResponse | "pass";
}

/** Counts a route's requests by source; over the limit, `429` with `error`; uncounted, `uncounted`. */
function perSource(
	counting: RateLimit,
	{ log, recorded }: Told,
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
				attributes: {
					name,
					limit,
					source,
					outcome: uncounted === "pass" ? "let_through" : "refused",
				},
			});
			return uncounted;
		}
		if (hit.kind === "allowed") return "pass" as const;
		const seconds = String(Math.ceil(hit.retryAfterMs / 1000));
		return jsonAnswer(429, { error }, { headers: { "retry-after": seconds } });
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

const every = ["GET", "POST", "PUT", "DELETE"] as const;

/** Both policies count every method by source; contributed alike by the module and its stand-in. */
export const perSourceMark: Mark = {
	guarantee: "per-source",
	policies: [
		{ policy: attemptsPerSource, methods: every },
		{ policy: requestsPerSource, methods: every },
	],
};
