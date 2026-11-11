import { Unavailable } from "@mod/kernel";
import type { Json, WriteOptions } from "@mod/store";
import { type DeferredSize, shardOf } from "./shards.ts";
import {
	type Attempt,
	again,
	type Changed,
	claim,
	confirmedAsRead,
	expiryOf,
	markedAt,
	nameOf,
	type Place,
	plainDoor,
	retried,
	rewrite,
	untilAnswered,
} from "./writing/writing.ts";

export {
	checkedCap,
	type KeyedSets,
	type KeyedSetWrite,
	keyedSetsIn,
	type Member,
	overCap,
} from "./keyed-sets/keyed-sets.ts";
export { type Attempt, type Changed, type Place, writeDeadline } from "./writing/writing.ts";
export type { DeferredSize };

/** Records of one shape by key, each changed atomically from what it holds. */
export function recordsIn<T extends Json>(place: Place) {
	plainDoor(place);
	claim(place, "records");
	return recordsOf<T>(place);
}

function recordsOf<T extends Json>(place: Place) {
	const keyOf = (key: string) => ({ space: place.space, partition: key, name: "record" });
	return {
		scan: async (
			cursor?: string,
		): Promise<{ readonly keys: string[]; readonly cursor?: string }> => {
			const page = await place.store.scan(place.space, cursor);
			const keys = page.keys.filter((k) => k.name === "record").map((k) => k.partition);
			return page.cursor === undefined ? { keys } : { keys, cursor: page.cursor };
		},
		/**
		 * Places the record unless the key holds one; a value given as a function is made from the
		 * attempt's deadline, again on each attempt. Throws Unavailable when the store cannot tell.
		 */
		create: async (
			key: string,
			value: T | ((attempt: Attempt) => T),
			lifetimeMs: number | "endless",
		): Promise<"created" | "exists"> =>
			retried(async () => {
				const marked = markedAt(place, await place.store.now());
				const options: WriteOptions = {
					expiry: lifetimeMs === "endless" ? { kind: "never" } : { kind: "after", ms: lifetimeMs },
					...marked,
				};
				const made = typeof value === "function" ? value({ deadline: marked.deadline }) : value;
				const written = await untilAnswered(() =>
					place.store.putIfAbsent(keyOf(key), made, options),
				);
				if (written.kind === "written") return "created";
				if (written.kind !== "exists") throw new Unavailable("records");
				const { entry } = await place.store.get(keyOf(key));
				if (!entry) return again;
				if (await confirmedAsRead(place, keyOf(key), entry.version, marked.deadline)) {
					return "exists";
				}
				return again;
			}),
		read: async (key: string): Promise<T | undefined> => {
			const { entry } = await place.store.get(keyOf(key));
			return entry?.value as T | undefined;
		},
		/**
		 * Removes the record whatever it holds. An absence may be another's removal not confirmed yet,
		 * so a write of its own made only while the key holds none confirms it; else it tries again.
		 */
		remove: (key: string): Promise<void> =>
			retried(async () => {
				const options = markedAt(place, await place.store.now());
				const taken = await untilAnswered(() => place.store.take(keyOf(key), options));
				if (taken.kind === "late" || taken.kind === "reused") throw new Unavailable("records");
				if (taken.kind !== "missing") return;
				if (await confirmedAsRead(place, keyOf(key), undefined, options.deadline)) return;
				return again;
			}),
		/**
		 * Changes the record from what it holds now; `change` runs again on a lost race, so it must be
		 * pure, and is handed the deadline that attempt is written with. Lifetimes are relative and kept
		 * by the store. Nothing when the key holds no record.
		 */
		change: async (
			key: string,
			change: (current: T, attempt: Attempt) => Changed<T> | undefined,
		): Promise<{ readonly before: T; readonly after: T } | undefined> => {
			const { before, after } = await rewrite(place, keyOf(key), (current, attempt) => {
				const changed = current === undefined ? undefined : change(current as T, attempt);
				return changed && { value: changed.value, expiry: expiryOf(changed.lifetimeMs) };
			});
			if (before === undefined) return undefined;
			return { before: before as T, after: after as T };
		},
	};
}

export type Records<T extends Json> = ReturnType<typeof recordsIn<T>>;

export {
	type ChangedRecord,
	changeRecords,
	changesTogether,
	changeTogether,
	type Next,
	pairedRecordsAcross,
	pairedRecordsIn,
	type Target,
} from "./together/together.ts";

/** Records under a name made per space from an unguessable secret; the store never receives it. */
export function secretRecordsIn<T extends Json>(place: Place) {
	plainDoor(place);
	claim(place, "secret records");
	const named = recordsOf<T>(place);
	const nameFor = (secret: string) => nameOf(place.space, secret);
	return {
		nameOf: nameFor,
		create: (secret: string, value: T, lifetimeMs: number | "endless") =>
			named.create(nameFor(secret), value, lifetimeMs),
		read: (secret: string) => named.read(nameFor(secret)),
		change: (secret: string, change: (current: T) => Changed<T> | undefined) =>
			named.change(nameFor(secret), change),
		remove: (secret: string) => named.remove(nameFor(secret)),
		named,
	};
}

/** Work that must be done later, kept until it is said done. */
export function deferredIn(place: Place & DeferredSize) {
	plainDoor(place);
	const shardKey = (shard: number) => ({
		space: place.space,
		partition: `jobs-${shard}`,
		name: "jobs",
	});
	const jobsIn = (value: Json | undefined) => (value ?? []) as readonly string[];
	return {
		/** Keeps the job; past a full shard it is refused as unavailable, and logged. */
		add: async (job: string): Promise<void> => {
			const { after } = await rewrite(place, shardKey(shardOf(job, place)), (current) => {
				const jobs = jobsIn(current);
				const listed = jobs.includes(job);
				if (!listed && jobs.length >= place.perShard) return undefined;
				// Listed work is written again, as the listing may be another request's not yet confirmed.
				return { value: listed ? jobs : [...jobs, job], expiry: { kind: "never" } };
			});
			if (!jobsIn(after).includes(job)) {
				place.log?.error("records.full", { space: place.space.name });
				throw new Unavailable("records");
			}
		},
		done: async (job: string): Promise<void> => {
			await rewrite(place, shardKey(shardOf(job, place)), (current) => {
				const jobs = jobsIn(current).filter((kept) => kept !== job);
				return { value: jobs, expiry: { kind: "keep" } };
			});
		},
		/** Hands each kept job to `handle`; a job whose handling fails, or a shard that cannot be read, stays and is counted. */
		each: async (handle: (job: string) => Promise<void>): Promise<{ readonly failed: number }> => {
			let failed = 0;
			for (let shard = 0; shard < place.shards; shard++) {
				const read = await place.store.get(shardKey(shard)).catch(() => undefined);
				if (!read) {
					failed++;
					continue;
				}
				for (const job of jobsIn(read.entry?.value)) {
					await handle(job).catch(() => {
						failed++;
					});
				}
			}
			return { failed };
		},
	};
}

export type Deferred = ReturnType<typeof deferredIn>;
