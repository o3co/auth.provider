import { Unavailable } from "@mod/kernel";
import { codePointOrder, type Json } from "@mod/store";
import {
	type Attempt,
	type Changed,
	checkedCap,
	type KeyedSets,
	type Next,
	overCap,
	writeDeadline,
} from "./records.ts";
import { type DeferredSize, shardOf } from "./shards.ts";

/** Jobs that all land in one shard of deferred work, and how many that shard keeps before it refuses. */
export function crowdingFor(size: DeferredSize) {
	return {
		limit: size.perShard,
		/** `count` jobs: one past the limit and at least one kept, so at least two. */
		jobs: (count: number): readonly [string, string, ...string[]] => {
			if (!(count >= 2)) throw new RangeError("crowdingFor: count is at least 2");
			const found: string[] = [];
			for (let i = 0; found.length < count; i++) {
				if (shardOf(`crowd-${i}`, size) === 0) found.push(`crowd-${i}`);
			}
			return found as unknown as readonly [string, string, ...string[]];
		},
	};
}

/**
 * Records, deferred work and keyed sets kept in memory, for tests of what a feature decides on what they
 * answer. Lifetimes run on the given clock. A change can meet another writer first, as a race would.
 */
export function memoryRecords<T extends Json>(now: () => number, size: DeferredSize) {
	const kept = new Map<string, { value: T; until: number }>();
	const jobs = new Set<string>();
	let other: ((value: T) => T) | undefined;
	const live = (key: string) => {
		const found = kept.get(key);
		if (found && found.until > now()) return found;
		kept.delete(key);
		return undefined;
	};
	const sets = new Map<string, Map<string, number>>();
	const awaiting = new Map<string, Map<string, number>>();
	const liveIn = (key: string) =>
		[...(sets.get(key) ?? new Map<string, number>())].filter(([, until]) => until > now());
	const keyedSets = (asked: number): KeyedSets => {
		const cap = checkedCap(asked);
		return {
			add: async (key, member, lifetimeMs) => {
				const members = new Map(liveIn(key));
				members.set(member, Math.max(members.get(member) ?? 0, now() + lifetimeMs));
				const byEnd = [...members].sort((a, b) => a[1] - b[1] || codePointOrder(a[0], b[0]));
				const { held, out: pushedOut } = overCap(byEnd, member, cap);
				sets.set(key, new Map(held));
				const waiting = awaiting.get(key) ?? new Map<string, number>();
				for (const name of pushedOut) waiting.set(name, members.get(name) ?? now());
				awaiting.set(key, waiting);
				return { pushedOut };
			},
			members: async (key) =>
				liveIn(key)
					.map(([member, until]) => ({ member, remainingMs: until - now() }))
					.sort((a, b) => codePointOrder(a.member, b.member)),
			remove: async (key, member) => {
				sets.get(key)?.delete(member);
			},
			awaiting: async (key) =>
				[...(awaiting.get(key) ?? new Map<string, number>())]
					.filter(([, until]) => until > now())
					.map(([member]) => member)
					.sort(codePointOrder),
			settled: async (key, member) => {
				awaiting.get(key)?.delete(member);
			},
		};
	};
	/** Writes the next of a record of the stand-in over the one read (`held`), answering what it holds after. */
	const apply = (key: string, held: ReturnType<typeof live>, next: Next<T>) => {
		if (next === undefined) return held?.value;
		if ("remove" in next) {
			kept.delete(key);
			return undefined;
		}
		const ms = next.lifetimeMs;
		const until =
			ms === undefined
				? (held?.until ?? Number.POSITIVE_INFINITY)
				: ms === "endless"
					? Number.POSITIVE_INFINITY
					: // A lifetime under 1 ms is 1 ms, as records keeps it.
						now() + Math.max(1, ms);
		kept.set(key, { value: next.value, until });
		return next.value;
	};
	return {
		/** Keyed sets in memory, as records keeps them, at most `cap` to a key. */
		keyedSets,
		records: {
			scan: async (): Promise<{ readonly keys: string[]; readonly cursor?: string }> => ({
				keys: [...kept.keys()].filter((key) => live(key)),
			}),
			create: async (
				key: string,
				value: T | ((attempt: Attempt) => T),
				lifetimeMs: number | "endless",
			): Promise<"created" | "exists"> => {
				if (live(key)) return "exists";
				const until = lifetimeMs === "endless" ? Number.POSITIVE_INFINITY : now() + lifetimeMs;
				const made =
					typeof value === "function" ? value({ deadline: writeDeadline(now()) }) : value;
				kept.set(key, { value: made, until });
				return "created";
			},
			read: async (key: string): Promise<T | undefined> => {
				return live(key)?.value;
			},
			remove: async (key: string): Promise<void> => {
				kept.delete(key);
			},
			change: async (
				key: string,
				change: (current: T, attempt: Attempt) => Changed<T> | undefined,
			): Promise<{ readonly before: T; readonly after: T } | undefined> => {
				let found = live(key);
				if (!found) return undefined;
				if (other) {
					// The change ran on what it read, then lost the race: it runs again on the other write.
					change(found.value, { deadline: writeDeadline(now()) });
					found = { value: other(found.value), until: found.until };
					kept.set(key, found);
					other = undefined;
				}
				const changed = change(found.value, { deadline: writeDeadline(now()) });
				if (!changed) return { before: found.value, after: found.value };
				const ms = changed.lifetimeMs;
				const until =
					ms === undefined ? found.until : ms === "endless" ? Number.POSITIVE_INFINITY : now() + ms;
				kept.set(key, { value: changed.value, until });
				return { before: found.value, after: changed.value };
			},
			/**
			 * Changes two records of this stand-in as one, from what both hold and the records `watch`
			 * names besides, as records' `changeTogether` does (nothing can come between, in memory).
			 */
			changeTogether: async (
				firstKey: string,
				secondKey: string,
				p: {
					readonly watch?: (first: T | undefined, second: T | undefined) => readonly string[];
					readonly decide: (
						first: T | undefined,
						second: T | undefined,
						watched: readonly (T | undefined)[],
					) => { readonly first?: Next<T>; readonly second?: Next<T> };
				},
			) => {
				if (firstKey === secondKey) throw new Error("records changed together are two records");
				const read = { first: live(firstKey), second: live(secondKey) };
				const before = { first: read.first?.value, second: read.second?.value };
				const watched = (p.watch?.(before.first, before.second) ?? []).map(
					(key) => live(key)?.value,
				);
				const decided = p.decide(before.first, before.second, watched);
				return {
					first: { before: before.first, after: apply(firstKey, read.first, decided.first) },
					second: { before: before.second, after: apply(secondKey, read.second, decided.second) },
				};
			},
			/**
			 * Changes records of this stand-in as one: the keys, and the ones `watch` names from what they
			 * hold, as records' `changeRecords` does (nothing can come between, in memory).
			 */
			changeRecords: async (
				keys: readonly string[],
				p: {
					readonly watch?: (read: readonly (T | undefined)[]) => readonly string[];
					readonly decide: (
						read: readonly (T | undefined)[],
						watched: readonly (T | undefined)[],
					) => { readonly targets?: readonly Next<T>[]; readonly watched?: readonly Next<T>[] };
				},
			) => {
				if (keys.length === 0) throw new Error("records changed together name one at least");
				if (new Set(keys).size !== keys.length) {
					throw new Error("records changed together are named once each");
				}
				// Each record read once, before the decision, and written over what was read.
				const held = new Map<string, ReturnType<typeof live>>();
				const readOnce = (key: string) => {
					if (!held.has(key)) held.set(key, live(key));
					return held.get(key)?.value;
				};
				const read = keys.map(readOnce);
				const named = p.watch?.(read) ?? [];
				const decided = p.decide(read, named.map(readOnce));
				const nexts = new Map<string, Next<T>>();
				const set = (key: string, next: Next<T>) => {
					if (next === undefined) return;
					if (nexts.has(key)) throw new Error("a record changed together is written once");
					nexts.set(key, next);
				};
				for (const [at, key] of keys.entries()) set(key, decided.targets?.[at]);
				for (const [at, key] of named.entries()) set(key, decided.watched?.[at]);
				const after = new Map(
					[...held].map(([key, was]) => [key, apply(key, was, nexts.get(key))] as const),
				);
				const changed = (key: string) => ({ before: held.get(key)?.value, after: after.get(key) });
				return { targets: keys.map(changed), watched: named.map(changed) };
			},
		},
		deferred: {
			add: async (job: string): Promise<void> => {
				const shard = shardOf(job, size);
				const crowded = [...jobs].filter((listed) => shardOf(listed, size) === shard).length;
				if (!jobs.has(job) && crowded >= size.perShard) throw new Unavailable("records stand-in");
				jobs.add(job);
			},
			done: async (job: string): Promise<void> => {
				jobs.delete(job);
			},
			each: async (
				handle: (job: string) => Promise<void>,
			): Promise<{ readonly failed: number }> => {
				let failed = 0;
				for (const job of [...jobs]) {
					await handle(job).catch(() => {
						failed++;
					});
				}
				return { failed };
			},
		},
		/** Before the next change writes, another writer changes the record as given. */
		raceNextChange: (write: (value: T) => T) => {
			other = write;
		},
		/** The work kept until done. */
		pending: () => [...jobs],
		/** What a key holds while it lives. */
		peek: (key: string) => live(key)?.value,
	};
}
