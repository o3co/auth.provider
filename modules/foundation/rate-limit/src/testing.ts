import { marks, policies } from "@mod/http";
import { contract, defineModule } from "@mod/kernel";
import type { Json } from "@mod/store";
import { attemptLimit, lockouts, type RateLimit, rateLimit } from "./contract.ts";
import { type LockoutStates, lockoutCounter } from "./lockout.ts";
import { retryAfterMs } from "./partition.ts";
import { limitingAttempts, limitingRequests, perSourceMark } from "./per-source.ts";

const idOf = (name: string, key: string) => `${name}\n${key}`;

/** Fixed windows on the composition's clock, as the store counts them. */
function memoryCounter(now: () => number): RateLimit {
	const counts = new Map<string, { n: number; resetAt: number }>();
	return {
		hit: async (name, key, window) => {
			const at = now();
			const id = idOf(name, key);
			const held = counts.get(id);
			if (!held || held.resetAt <= at) {
				if (window.limit < 1) return { kind: "limited", retryAfterMs: window.ms };
				counts.set(id, { n: 1, resetAt: at + window.ms });
				return { kind: "allowed" };
			}
			if (held.n >= window.limit) {
				return { kind: "limited", retryAfterMs: retryAfterMs(window, held.resetAt, at) };
			}
			held.n += 1;
			return { kind: "allowed" };
		},
	};
}

/** Expiry is left out: a state that would have expired already judges as nothing held. */
function memoryStates(now: () => number): LockoutStates {
	const states = new Map<string, Json>();
	return {
		read: async (name, key) => {
			const value = states.get(idOf(name, key));
			return value === undefined ? { now: now() } : { value, now: now() };
		},
		change: async (name, key, decide) => {
			const id = idOf(name, key);
			const decision = decide(states.get(id), now());
			if (decision.kind === "write") states.set(id, decision.value);
			if (decision.kind === "remove") states.delete(id);
		},
	};
}

/** One composition's counts, shared by its limits and policies as the real module's spaces are. */
const memory = contract<{
	readonly windows: RateLimit;
	readonly attempts: RateLimit;
	readonly lockouts: LockoutStates;
}>("rate-limit.memory");

const noAudit = { record: () => {} };

/** Every limit, lockout and per-source policy, counted in memory with no store and no audit. */
export const rateLimitStandIn = defineModule(
	{ name: "rate-limit", replicaSafe: false, takes: [] },
	(m) => [
		m.provide(memory).by((c) => ({
			windows: memoryCounter(c.clock.now),
			attempts: memoryCounter(c.clock.now),
			lockouts: memoryStates(c.clock.now),
		})),
		m.provide(rateLimit).by(async (c) => (await c.get(memory)).windows),
		m.provide(attemptLimit).by(async (c) => (await c.get(memory)).attempts),
		m.provide(lockouts).by(async (c) => lockoutCounter((await c.get(memory)).lockouts)),
		m.contribute(policies).by(async (c) =>
			limitingAttempts((await c.get(memory)).attempts, {
				log: c.log,
				recorded: noAudit,
			}),
		),
		m
			.contribute(policies)
			.by(async (c) =>
				limitingRequests(
					(await c.get(memory)).windows,
					{ log: c.log, recorded: noAudit },
					"closed",
				),
			),
		m.contribute(marks).by(() => perSourceMark),
	],
);
