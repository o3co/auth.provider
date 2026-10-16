import { audit } from "@mod/audit";
import { policies } from "@mod/http";
import { defineModule, Unavailable } from "@mod/kernel";
import { type Space, type Store, spaces, store } from "@mod/store";
import { z } from "zod";
import { attemptLimit, lockouts, type RateLimit, rateLimit } from "./contract.ts";
import { lockoutCounter, lockoutSpace, storedStates } from "./lockout.ts";
import { partitionOf, retryAfterMs } from "./partition.ts";
import { limitingAttempts, limitingRequests } from "./per-source.ts";

/** Kept from eviction, which a flood of requests could otherwise force to reset the count. */
const windows: Space = { name: "rate-limit.windows", guarantees: ["no-eviction"] };
/** Also replicated: losing a count over a failover would lift a limit that guards credentials. */
const attemptWindows: Space = {
	name: "rate-limit.attempts",
	guarantees: ["no-eviction", "replicated"],
};

function counter(saved: Store, space: Space, now: () => number): RateLimit {
	return {
		hit: async (name, key, window) => {
			const partition = partitionOf(name, key);
			const counted = await saved.count({ space, partition, name: "n" }, window);
			if (counted.kind === "counted") return { kind: "allowed" };
			// A late or reused count may or may not have landed; it is not told as either.
			if (counted.kind !== "limited") throw new Unavailable("rate-limit");
			return { kind: "limited", retryAfterMs: retryAfterMs(window, counted.resetAt, now()) };
		},
	};
}

const section = z.strictObject({
	"fail-mode": z
		.enum(["open", "closed"])
		.default("closed")
		.describe(
			"What a route's request limit does when the store cannot count: `closed` answers 503, `open` lets the request through.",
		),
});

export default defineModule({ name: "rate-limit", section }, (m) => [
	m.contribute(spaces).by(() => windows),
	m.contribute(spaces).by(() => attemptWindows),
	m.contribute(spaces).by(() => lockoutSpace),
	m.provide(rateLimit).by(async (c) => counter(await c.get(store), windows, c.clock.now)),
	m.provide(attemptLimit).by(async (c) => counter(await c.get(store), attemptWindows, c.clock.now)),
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
]);
