import { erasers } from "@mod/erasure-extensions";
import { marks, policies } from "@mod/http-server";
import { contract, defineModule } from "@mod/kernel";
import type { Expiry, Json } from "@mod/store";
import { attemptLimit, lockouts, type RateLimit, rateLimit, subjectLockouts } from "./contract.ts";
import { lockoutEraser } from "./drop/drop.ts";
import { type LockoutStates, lockoutCounter } from "./lockout/lockout.ts";
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

/** When a write's expiry ends it, as the store judges it from the entry's own: `null` never. */
function endOf(expiry: Expiry, held: number | null | undefined, at: number): number | null {
	switch (expiry.kind) {
		case "after":
			return at + expiry.ms;
		case "at":
			return expiry.at;
		case "never":
			return null;
		case "keep":
			return held ?? null;
		case "extend":
			return held === null ? null : Math.max(held ?? 0, at + expiry.ms);
	}
}

/** States kept as the store keeps them: an entry is gone from its expiry on, so the eraser counts as it does. */
function memoryStates(now: () => number): LockoutStates {
	const states = new Map<string, { readonly value: Json; readonly endsAt: number | null }>();
	const live = (id: string, at: number) => {
		const held = states.get(id);
		if (held?.endsAt != null && held.endsAt <= at) states.delete(id);
		return states.get(id);
	};
	return {
		read: async (name, key) => {
			const at = now();
			const held = live(idOf(name, key), at);
			return held === undefined ? { now: at } : { value: held.value, now: at };
		},
		change: async (name, key, decide) => {
			const id = idOf(name, key);
			const at = now();
			const held = live(id, at);
			const decision = decide(held?.value, at);
			if (decision.kind === "remove") states.delete(id);
			if (decision.kind !== "write") return;
			const endsAt = endOf(decision.expiry, held?.endsAt, at);
			if (endsAt !== null && endsAt <= at) states.delete(id);
			else states.set(id, { value: decision.value, endsAt });
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
	{ name: "rate-limit", replicaSafe: false, takes: [subjectLockouts] },
	(m) => [
		m.provide(memory).by((c) => ({
			windows: memoryCounter(c.clock.now),
			attempts: memoryCounter(c.clock.now),
			lockouts: memoryStates(c.clock.now),
		})),
		m.provide(rateLimit).by(async (c) => (await c.get(memory)).windows),
		m.provide(attemptLimit).by(async (c) => (await c.get(memory)).attempts),
		m.provide(lockouts).by(async (c) => lockoutCounter((await c.get(memory)).lockouts)),
		// The same eraser over the memory states; it declares no space, holding none in a store.
		m
			.contribute(erasers)
			.by(async (c) =>
				lockoutEraser((await c.get(memory)).lockouts, await c.collect(subjectLockouts)),
			),
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
