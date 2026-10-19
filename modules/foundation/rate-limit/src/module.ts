import { audit } from "@mod/audit";
import { marks, policies } from "@mod/http";
import { contract, defineModule, isUnavailable, Unavailable } from "@mod/kernel";
import { type Counter, instruments, counter as metricCounter } from "@mod/metrics";
import { type Space, type Store, spaces, store } from "@mod/store";
import { z } from "zod";
import { attemptLimit, lockouts, type RateLimit, rateLimit, type Window } from "./contract.ts";
import { lockoutCounter, lockoutSpace, storedStates } from "./lockout.ts";
import { partitionOf, retryAfterMs } from "./partition.ts";
import { limitingAttempts, limitingRequests, perSourceMark } from "./per-source.ts";

/** Kept from eviction, which a flood of requests could otherwise force to reset the count. */
const windows: Space = { name: "rate-limit.windows", guarantees: ["no-eviction"] };
/** Also replicated: losing a count over a failover would lift a limit that guards credentials. */
const attemptWindows: Space = {
	name: "rate-limit.attempts",
	guarantees: ["no-eviction", "replicated"],
};

type Limit = "attempts" | "requests";

/** Uses the store could not count, by limit; made at each build, and recording only once metrics takes it. */
const uncounted = contract<Counter<"limit">>("rate-limit.uncounted");

function counter(saved: Store, space: Space, limit: Limit, told: Told): RateLimit {
	const count = async (name: string, key: string, window: Window) => {
		const counted = await saved.count(
			{ space, partition: partitionOf(name, key), name: "n" },
			window,
		);
		if (counted.kind === "counted") return { kind: "allowed" } as const;
		// A late or reused count may or may not have landed; it is not told as either.
		if (counted.kind !== "limited") throw new Unavailable("rate-limit");
		const wait = retryAfterMs(window, counted.resetAt, told.now());
		return { kind: "limited", retryAfterMs: wait } as const;
	};
	return {
		hit: (name, key, window) =>
			count(name, key, window).catch((failure: unknown) => {
				if (isUnavailable(failure)) told.uncounted.add({ limit });
				throw failure;
			}),
	};
}

interface Told {
	readonly uncounted: Counter<"limit">;
	readonly now: () => number;
}

const section = z.strictObject({
	"fail-mode": z
		.enum(["open", "closed"])
		.prefault("closed")
		.describe(
			"What a route's request limit does when the store cannot count: `closed` answers 503, `open` lets the request through.",
		),
});

export default defineModule({ name: "rate-limit", section }, (m) => [
	m.provide(uncounted).by(() =>
		metricCounter({
			name: "auth_rate_limit_uncounted_total",
			help: "Uses a limit could not count as the store could not tell, by limit.",
			labels: { limit: ["attempts", "requests"] },
		}),
	),
	m.contribute(instruments).by((c) => c.get(uncounted)),
	m.contribute(spaces).by(() => windows),
	m.contribute(spaces).by(() => attemptWindows),
	m.contribute(spaces).by(() => lockoutSpace),
	m.provide(rateLimit).by(async (c) =>
		counter(await c.get(store), windows, "requests", {
			uncounted: await c.get(uncounted),
			now: c.clock.now,
		}),
	),
	m.provide(attemptLimit).by(async (c) =>
		counter(await c.get(store), attemptWindows, "attempts", {
			uncounted: await c.get(uncounted),
			now: c.clock.now,
		}),
	),
	m.provide(lockouts).by(async (c) => lockoutCounter(storedStates(await c.get(store)))),
	m
		.contribute(policies)
		.by(async (c) =>
			limitingAttempts(await c.get(attemptLimit), { log: c.log, recorded: await c.get(audit) }),
		),
	m
		.contribute(policies)
		.by(async (c) =>
			limitingRequests(
				await c.get(rateLimit),
				{ log: c.log, recorded: await c.get(audit) },
				c.section["fail-mode"],
			),
		),
	m.contribute(marks).by(() => perSourceMark),
]);
