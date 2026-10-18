import { Unavailable } from "@mod/kernel";
import { codePointOrder, type Json } from "@mod/store";
import { type Changed, checkedCap, type KeyedSets, overCap } from "./records.ts";
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
	return {
		/** Keyed sets in memory, as records keeps them, at most `cap` to a key. */
		keyedSets,
		records: {
			scan: async (): Promise<{ readonly keys: string[]; readonly cursor?: string }> => ({
				keys: [...kept.keys()].filter((key) => live(key)),
			}),
			create: async (
				key: string,
				value: T,
				lifetimeMs: number | "endless",
			): Promise<"created" | "exists"> => {
				if (live(key)) return "exists";
				const until = lifetimeMs === "endless" ? Number.POSITIVE_INFINITY : now() + lifetimeMs;
				kept.set(key, { value, until });
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
				change: (current: T) => Changed<T> | undefined,
			): Promise<{ readonly before: T; readonly after: T } | undefined> => {
				let found = live(key);
				if (!found) return undefined;
				if (other) {
					// The change ran on what it read, then lost the race: it runs again on the other write.
					change(found.value);
					found = { value: other(found.value), until: found.until };
					kept.set(key, found);
					other = undefined;
				}
				const changed = change(found.value);
				if (!changed) return { before: found.value, after: found.value };
				const ms = changed.lifetimeMs;
				const until =
					ms === undefined ? found.until : ms === "endless" ? Number.POSITIVE_INFINITY : now() + ms;
				kept.set(key, { value: changed.value, until });
				return { before: found.value, after: changed.value };
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
