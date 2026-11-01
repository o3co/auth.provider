import { deepFreeze, type Runtime } from "@mod/kernel";
import {
	type BatchWrite,
	type Condition,
	canonicalJson,
	checkedStore,
	type Entry,
	type Expiry,
	idempotencyRequest,
	type Json,
	type Key,
	type Late,
	type Reused,
	type Space,
	type Store,
} from "./contract.ts";

type Answer = { readonly kind: string };
type Held = { readonly value: Json; readonly version: string; readonly expiresAt: number | null };
type Limits = { readonly deadline?: number; readonly idempotency?: string } | undefined;

/** How long past a deadline a resend still gets the first answer. */
export const idempotencySkewMs = 1000;
export const idempotencyDefaultMs = 5 * 60_000;
const sweepEvery = 256;
const scanPage = 100;

const id = (key: Key) => JSON.stringify([key.space.name, key.partition, key.name]);
const partitionOf = (key: Key) => JSON.stringify([key.space.name, key.partition]);
/** Expired at exactly its expiry, for reads and writes alike, so the two agree at that instant. */
const live = (held: { expiresAt: number | null } | undefined, now: number) =>
	held !== undefined && (held.expiresAt === null || held.expiresAt > now);

/** Expiry for a new write given the entry's current expiry (undefined when there is none). */
export function resolveExpiry(
	expiry: Expiry,
	current: number | null | undefined,
	now: number,
): number | null {
	switch (expiry.kind) {
		case "after":
			return now + expiry.ms;
		case "at":
			return expiry.at;
		case "never":
			return null;
		case "keep":
			return current ?? null;
		case "extend":
			if (current === null) return null;
			return Math.max(current ?? 0, now + expiry.ms);
	}
}

function entryOf(held: Held): Entry {
	return deepFreeze({
		value: structuredClone(held.value),
		version: held.version,
		expiresAt: held.expiresAt,
	});
}

/** Counts versions from one, never naming one twice within the store. */
const counting = () => {
	let last = 0;
	return () => String(++last);
};

/** A store in memory; `nextVersion` names each written version, by default from its own count. */
export function memoryStore(
	clock: Runtime["clock"],
	declared: readonly Space[],
	nextVersion: () => string = counting(),
): Store {
	const values = new Map<string, Held>();
	const counters = new Map<string, { count: number; resetAt: number }>();
	const answers = new Map<string, { digest: string; answer: Answer; until: number }>();
	let operations = 0;

	const sweep = (now: number) => {
		if (++operations % sweepEvery !== 0) return;
		for (const [k, v] of values) if (!live(v, now)) values.delete(k);
		for (const [k, v] of answers) if (v.until <= now) answers.delete(k);
		for (const [k, v] of counters) if (v.resetAt <= now) counters.delete(k);
	};
	const current = (key: Key, now: number) => {
		const held = values.get(id(key));
		if (live(held, now)) return held;
		values.delete(id(key));
		return undefined;
	};
	/**
	 * A batch at `now`, as one: every condition checked first, the first not met answered by its
	 * index with nothing written; else every write made, each version (none for a removal) answered.
	 */
	const applyBatch = (
		conditions: readonly Condition[],
		writes: readonly BatchWrite[],
		now: number,
	) => {
		for (const [index, condition] of conditions.entries()) {
			const held = current(condition.key, now);
			const holds = "absent" in condition ? !held : held?.version === condition.version;
			if (!holds) return { kind: "conflict" as const, index };
		}
		const versions = writes.map((w) => {
			if ("remove" in w) {
				values.delete(id(w.key));
				return null;
			}
			return write(w.key, w.put, w.expiry, now);
		});
		return { kind: "committed" as const, versions };
	};
	/** Runs a write once per idempotency mark and request, refusing it after its deadline. */
	const guarded = async <A extends Answer>(
		partition: string | undefined,
		request: string,
		options: Limits,
		apply: (now: number) => A,
	): Promise<A | Late | Reused> => {
		const now = clock.now();
		sweep(now);
		const mark =
			partition && options?.idempotency && JSON.stringify([partition, options.idempotency]);
		if (mark) {
			const seen = answers.get(mark);
			if (seen && seen.until > now)
				return seen.digest === request ? (seen.answer as A) : { kind: "reused" };
		}
		const late = options?.deadline !== undefined && now > options.deadline;
		const answer = late
			? deepFreeze({ kind: "late" as const })
			: deepFreeze(structuredClone(apply(now)));
		if (mark) {
			const until = (options?.deadline ?? now + idempotencyDefaultMs) + idempotencySkewMs;
			answers.set(mark, { digest: request, answer, until });
		}
		return answer;
	};
	/**
	 * Runs a batch across partitions once per mark and request: the mark is looked for in every
	 * partition first, kept in each with one answer and one end, never rewritten when reused, and a
	 * late answer is not kept.
	 */
	const guardedAcross = async <A extends Answer>(
		partitions: readonly string[],
		request: string,
		options: Limits,
		apply: (now: number) => A,
	): Promise<A | Late | Reused> => {
		const now = clock.now();
		sweep(now);
		const marks = options?.idempotency
			? partitions.map((partition) => JSON.stringify([partition, options.idempotency]))
			: [];
		for (const mark of marks) {
			const seen = answers.get(mark);
			if (seen && seen.until > now)
				return seen.digest === request ? (seen.answer as A) : { kind: "reused" };
		}
		if (options?.deadline !== undefined && now > options.deadline) return { kind: "late" };
		const answer = deepFreeze(structuredClone(apply(now)));
		const until = (options?.deadline ?? now + idempotencyDefaultMs) + idempotencySkewMs;
		for (const mark of marks) answers.set(mark, { digest: request, answer, until });
		return answer;
	};
	const write = (key: Key, value: Json, expiry: Expiry, now: number) => {
		const before = current(key, now);
		const version = nextVersion();
		const expiresAt = resolveExpiry(expiry, before ? before.expiresAt : undefined, now);
		if (expiresAt !== null && expiresAt <= now) values.delete(id(key));
		else values.set(id(key), { value: JSON.parse(canonicalJson(value)), version, expiresAt });
		return version;
	};
	const samePartition = (keys: readonly Key[]) => {
		if (new Set(keys.map(partitionOf)).size > 1)
			throw new Error("keys span more than one partition");
	};

	return checkedStore(
		{
			get: async (key) => {
				const now = clock.now();
				const held = current(key, now);
				return { entry: held ? entryOf(held) : null, now };
			},
			putIfAbsent: (key, value, options) =>
				guarded(
					partitionOf(key),
					idempotencyRequest("putIfAbsent", [key], [value, options.expiry]),
					options,
					(now) => {
						const held = current(key, now);
						if (held) {
							return {
								kind: "exists" as const,
								remainingMs: held.expiresAt === null ? null : held.expiresAt - now,
							};
						}
						return { kind: "written" as const, version: write(key, value, options.expiry, now) };
					},
				),
			replaceIf: (key, version, value, options) =>
				guarded(
					partitionOf(key),
					idempotencyRequest("replaceIf", [key], [version, value, options.expiry]),
					options,
					(now) => {
						const held = current(key, now);
						if (!held) return { kind: "missing" as const };
						if (held.version !== version) return { kind: "conflict" as const };
						return { kind: "written" as const, version: write(key, value, options.expiry, now) };
					},
				),
			removeIf: (key, expected, options) =>
				guarded(
					partitionOf(key),
					idempotencyRequest("removeIf", [key], [expected]),
					options,
					(now) => {
						const held = current(key, now);
						if (!held) return { kind: "missing" as const };
						const matches =
							"version" in expected
								? held.version === expected.version
								: canonicalJson(held.value) === canonicalJson(expected.value);
						if (!matches) return { kind: "conflict" as const };
						values.delete(id(key));
						return { kind: "removed" as const, old: entryOf(held) };
					},
				),
			take: (key, options) =>
				guarded(partitionOf(key), idempotencyRequest("take", [key], []), options, (now) => {
					const held = current(key, now);
					if (!held) return { kind: "missing" as const };
					values.delete(id(key));
					return { kind: "taken" as const, entry: entryOf(held) };
				}),
			batchAcross: async (conditions, writes, options) => {
				const keys = [...conditions.map((c) => c.key), ...writes.map((w) => w.key)];
				const request = idempotencyRequest("batchAcross", keys, [
					conditions.map((c) => ("absent" in c ? { absent: true } : { version: c.version })),
					writes.map((w) => ("remove" in w ? null : [w.put, w.expiry])),
				]);
				const partitions = [...new Set(keys.map(partitionOf))];
				return guardedAcross(partitions, request, options, (now) =>
					applyBatch(conditions, writes, now),
				);
			},
			batch: async (conditions, writes, options) => {
				const keys = [...conditions.map((c) => c.key), ...writes.map((w) => w.key)];
				samePartition(keys);
				const request = idempotencyRequest("batch", keys, [
					conditions.map((c) => ("absent" in c ? { absent: true } : { version: c.version })),
					writes.map((w) => ("remove" in w ? null : [w.put, w.expiry])),
				]);
				return guarded(keys[0] && partitionOf(keys[0]), request, options, (now) =>
					applyBatch(conditions, writes, now),
				);
			},
			count: (key, window, options) =>
				guarded(
					partitionOf(key),
					idempotencyRequest("count", [key], [window.ms, window.limit]),
					options,
					(now) => {
						const held = counters.get(id(key));
						if (!held || held.resetAt <= now) {
							if (window.limit < 1) return { kind: "limited" as const, resetAt: now + window.ms };
							counters.set(id(key), { count: 1, resetAt: now + window.ms });
							return { kind: "counted" as const, count: 1, resetAt: now + window.ms };
						}
						if (held.count >= window.limit)
							return { kind: "limited" as const, resetAt: held.resetAt };
						held.count += 1;
						return { kind: "counted" as const, count: held.count, resetAt: held.resetAt };
					},
				),
			now: async () => clock.now(),
			scan: async (space, cursor) => {
				const now = clock.now();
				const ids = [...values]
					.filter(([at, held]) => live(held, now) && JSON.parse(at)[0] === space.name)
					.map(([at]) => at)
					.filter((at) => cursor === undefined || at > cursor)
					.sort();
				const page = ids.slice(0, scanPage);
				const keys = page.map((at) => {
					const [, partition, name] = JSON.parse(at) as [string, string, string];
					return { space, partition, name };
				});
				const last = page.at(-1);
				return deepFreeze(ids.length > scanPage && last ? { keys, cursor: last } : { keys });
			},
		},
		declared,
	);
}
