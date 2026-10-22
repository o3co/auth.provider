import { createHash } from "node:crypto";
import { type Clock, isUnavailable, type Log, type Random, Unavailable } from "@mod/kernel";
import {
	codePointOrder,
	type Expiry,
	type Json,
	type Key,
	type Space,
	type Store,
	type WriteOptions,
} from "@mod/store";
import { type DeferredSize, shardOf } from "./shards.ts";

export type { DeferredSize };

export interface Place {
	readonly store: Store;
	readonly space: Space;
	/** Where a refusal the caller cannot tell apart is told, with the space it came from. */
	readonly log?: Log;
	/** Where the unguessable marks that settle a resent write come from: the kernel's randomness. */
	readonly random: Random;
}

/** A changed value, and its new lifetime from the write, or none to end it; without one, the lifetime stays. */
export interface Changed<T> {
	readonly value: T;
	readonly lifetimeMs?: number | "endless";
}

/** A write is no longer resent once the pauses between its sends add up to this. */
const patienceMs = 10_000;
/** How many times a write is tried again after losing a race, before it answers unavailable. */
const attempts = 8;
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Sends one write until the store answers. Each resend is the same request under the same mark,
 * so a write whose answer was lost gets the answer it first had and never takes effect twice.
 * Patience is counted in pauses, so no clock is read.
 */
async function settled<A>(send: () => Promise<A>): Promise<A> {
	let waited = 0;
	let wait = 50;
	for (;;) {
		try {
			return await send();
		} catch (error) {
			if (!isUnavailable(error) || waited + wait > patienceMs) throw error;
		}
		await pause(wait);
		waited += wait;
		wait = Math.min(wait * 2, 1000);
	}
}

// A mark is random, not a hash of the write: two writers putting the same value on the same
// version would share a hashed mark, and the store would answer both as the one that wrote.
const markFrom = (place: Place) => Buffer.from(place.random.bytes(16)).toString("base64url");
/** Writes that land after this store-clock time are refused, so a lost send cannot act later. */
const deadlineFrom = (now: number) => now + patienceMs;
const markedAt = (place: Place, now: number) => ({
	idempotency: markFrom(place),
	deadline: deadlineFrom(now),
});

/** Writes a mark of its own only while the key holds what was read, at that version or none. */
async function confirmedAsRead(
	place: Place,
	key: Key,
	version: string | undefined,
	deadline: number,
) {
	const markKey = { space: key.space, partition: key.partition, name: "settled" };
	const marked = { idempotency: markFrom(place), deadline };
	const confirmed = await settled(() =>
		place.store.batch(
			[version === undefined ? { key, absent: true } : { key, version }],
			[{ key: markKey, put: true, expiry: { kind: "after", ms: 1 } }],
			marked,
		),
	);
	return confirmed.kind === "committed";
}

/**
 * Reads the key, decides on what it holds, and writes on exactly what was read, under a mark;
 * losing a race decides again on what is there now. Answers what the key held and holds now.
 */
async function rewrite(
	place: Place,
	key: Key,
	decide: (
		current: Json | undefined,
	) => { readonly value: Json; readonly expiry: Expiry } | undefined,
): Promise<{ readonly before: Json | undefined; readonly after: Json | undefined }> {
	for (let attempt = 0; attempt < attempts; attempt++) {
		const { entry, now } = await place.store.get(key);
		const before = entry?.value;
		const decided = decide(before);
		if (!decided) {
			if (await confirmedAsRead(place, key, entry?.version, deadlineFrom(now))) {
				return { before, after: before };
			}
			continue;
		}
		const options: WriteOptions = { expiry: decided.expiry, ...markedAt(place, now) };
		const written = entry
			? await settled(() => place.store.replaceIf(key, entry.version, decided.value, options))
			: await settled(() => place.store.putIfAbsent(key, decided.value, options));
		if (written.kind === "written") return { before, after: decided.value };
		if (written.kind === "late" || written.kind === "reused") throw new Unavailable("records");
	}
	throw new Unavailable("records");
}

function expiryOf(lifetimeMs: number | "endless" | undefined): Expiry {
	if (lifetimeMs === undefined) return { kind: "keep" };
	if (lifetimeMs === "endless") return { kind: "never" };
	return { kind: "after", ms: Math.max(1, lifetimeMs) };
}

/** The kind each space was opened for, by store: a space's scan lists every record's key, so it holds one kind. */
const openedFor = new WeakMap<Store, Map<string, "records" | "secret records">>();
function claim(place: Place, kind: "records" | "secret records") {
	const kinds = openedFor.get(place.store) ?? new Map<string, "records" | "secret records">();
	openedFor.set(place.store, kinds);
	const held = kinds.get(place.space.name);
	if (held !== undefined && held !== kind) {
		throw new Error(`a space holds records or secret records, not both: ${place.space.name}`);
	}
	kinds.set(place.space.name, kind);
}

/** Records of one shape by key, each changed atomically from what it holds. */
export function recordsIn<T extends Json>(place: Place) {
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
		/** Places the record unless the key holds one. Throws Unavailable when the store cannot tell. */
		create: async (
			key: string,
			value: T,
			lifetimeMs: number | "endless",
		): Promise<"created" | "exists"> => {
			for (let attempt = 0; attempt < attempts; attempt++) {
				const marked = markedAt(place, await place.store.now());
				const options: WriteOptions = {
					expiry: lifetimeMs === "endless" ? { kind: "never" } : { kind: "after", ms: lifetimeMs },
					...marked,
				};
				const written = await settled(() => place.store.putIfAbsent(keyOf(key), value, options));
				if (written.kind === "written") return "created";
				if (written.kind !== "exists") throw new Unavailable("records");
				const { entry } = await place.store.get(keyOf(key));
				if (!entry) continue;
				if (await confirmedAsRead(place, keyOf(key), entry.version, marked.deadline)) {
					return "exists";
				}
			}
			throw new Unavailable("records");
		},
		read: async (key: string): Promise<T | undefined> => {
			const { entry } = await place.store.get(keyOf(key));
			return entry?.value as T | undefined;
		},
		/**
		 * Removes the record whatever it holds. An absence may be another's removal not confirmed yet,
		 * so a write of its own made only while the key holds none confirms it; else it tries again.
		 */
		remove: async (key: string): Promise<void> => {
			for (let attempt = 0; attempt < attempts; attempt++) {
				const options = markedAt(place, await place.store.now());
				const taken = await settled(() => place.store.take(keyOf(key), options));
				if (taken.kind === "late" || taken.kind === "reused") throw new Unavailable("records");
				if (taken.kind !== "missing") return;
				if (await confirmedAsRead(place, keyOf(key), undefined, options.deadline)) return;
			}
			throw new Unavailable("records");
		},
		/**
		 * Changes the record from what it holds now; `change` runs again on a lost race, so it must be
		 * pure. Lifetimes are relative and kept by the store. Nothing when the key holds no record.
		 */
		change: async (
			key: string,
			change: (current: T) => Changed<T> | undefined,
		): Promise<{ readonly before: T; readonly after: T } | undefined> => {
			const { before, after } = await rewrite(place, keyOf(key), (current) => {
				const changed = current === undefined ? undefined : change(current as T);
				return changed && { value: changed.value, expiry: expiryOf(changed.lifetimeMs) };
			});
			if (before === undefined) return undefined;
			return { before: before as T, after: after as T };
		},
	};
}

export type Records<T extends Json> = ReturnType<typeof recordsIn<T>>;

/** A record by its place and key, where `changeTogether` reads or writes it. */
export interface Target {
	readonly place: Place;
	readonly key: string;
}

/** What `changeTogether` does to one record: set it (with a lifetime, or keeping its own), or remove it; none keeps it. */
export type Next<T> = Changed<T> | { readonly remove: true } | undefined;

/**
 * Two records of one place changed as one, from what both hold and the records of that place
 * `watch` names, as `changeTogether` does. Where the place's store cannot, `refuse` (the builder's)
 * is told, naming `where`: a wiring then maps it with no branch of its own.
 */
export function pairedRecordsIn<T extends Json>(
	place: Place,
	where: string,
	refuse: (where: string, reason: string) => never,
) {
	if (!changesTogether(place.store)) {
		refuse(where, "its store writes no records of two partitions as one");
	}
	claim(place, "records");
	const at = (key: string): Target => ({ place, key });
	return {
		changeTogether: (
			firstKey: string,
			secondKey: string,
			p: {
				readonly watch: (first: T | undefined, second: T | undefined) => readonly string[];
				readonly decide: (
					first: T | undefined,
					second: T | undefined,
					watched: readonly (T | undefined)[],
				) => { readonly first?: Next<T>; readonly second?: Next<T> };
			},
		) =>
			changeTogether<T, T>({
				first: at(firstKey),
				second: at(secondKey),
				watch: (first, second) => p.watch(first, second).map(at),
				decide: (first, second, watched) =>
					p.decide(first, second, watched as readonly (T | undefined)[]),
			}),
	};
}

/** Whether the store writes records of several partitions and spaces as one, as `changeTogether` asks. */
export function changesTogether(target: Store): boolean {
	return typeof target.batchAcross === "function";
}

const recordKey = (target: Target) => ({
	space: target.place.space,
	partition: target.key,
	name: "record",
});
const sameTarget = (a: Target, b: Target) =>
	a.place.space.name === b.place.space.name && a.key === b.key;

/**
 * Changes two records as one, from what both hold and what `watch` names besides: `decide` runs on
 * what was read, and everything read is held by a condition of the one write, so another writer of
 * any of them first makes it read all again, `watch` too, and decide again; it must be pure. A
 * record `watch` names that is the first or second is read once and held once. Every place is on
 * one store that writes as one (`changesTogether`); the records sit in spaces of one guarantee.
 */
export async function changeTogether<A extends Json, B extends Json>(p: {
	readonly first: Target;
	readonly second: Target;
	readonly watch?: (first: A | undefined, second: B | undefined) => readonly Target[];
	readonly decide: (
		first: A | undefined,
		second: B | undefined,
		watched: readonly (Json | undefined)[],
	) => { readonly first?: Next<A>; readonly second?: Next<B> };
}): Promise<{
	readonly first: { readonly before: A | undefined; readonly after: A | undefined };
	readonly second: { readonly before: B | undefined; readonly after: B | undefined };
}> {
	const { first, second } = p;
	const target = first.place.store;
	const batchAcross = target.batchAcross?.bind(target);
	if (!batchAcross) throw new Error("the store writes no records of two partitions as one");
	if (second.place.store !== target) throw new Error("records changed together share one store");
	if (sameTarget(first, second)) throw new Error("records changed together are two records");
	claim(first.place, "records");
	claim(second.place, "records");
	for (let attempt = 0; attempt < attempts; attempt++) {
		const marked = markedAt(first.place, await target.now());
		const [a, b] = await Promise.all([target.get(recordKey(first)), target.get(recordKey(second))]);
		const before = {
			first: a.entry?.value as A | undefined,
			second: b.entry?.value as B | undefined,
		};
		// Each record held once: the first and second, then what the watch names besides.
		const held: { target: Target; version: string | undefined; value: Json | undefined }[] = [
			{ target: first, version: a.entry?.version, value: a.entry?.value },
			{ target: second, version: b.entry?.version, value: b.entry?.value },
		];
		const named = p.watch?.(before.first, before.second) ?? [];
		for (const watched of named) {
			if (watched.place.store !== target)
				throw new Error("records changed together share one store");
			if (held.some((h) => sameTarget(h.target, watched))) continue;
			claim(watched.place, "records");
			const { entry } = await target.get(recordKey(watched));
			held.push({ target: watched, version: entry?.version, value: entry?.value });
		}
		const watchedValues = named.map((w) => held.find((h) => sameTarget(h.target, w))?.value);
		const decided = p.decide(before.first, before.second, watchedValues);
		const conditions = held.map((h) =>
			h.version === undefined
				? { key: recordKey(h.target), absent: true as const }
				: { key: recordKey(h.target), version: h.version },
		);
		const writeOf = (record: Target, next: Next<Json>) => {
			if (next === undefined) return [];
			if ("remove" in next) return [{ key: recordKey(record), remove: true as const }];
			return [{ key: recordKey(record), put: next.value, expiry: expiryOf(next.lifetimeMs) }];
		};
		const writes = [...writeOf(first, decided.first), ...writeOf(second, decided.second)];
		// Nothing to write: what was read is confirmed by a mark of its own, held by the same conditions.
		const sent =
			writes.length > 0
				? writes
				: [
						{
							key: { ...recordKey(first), name: "settled" },
							put: true,
							expiry: { kind: "after", ms: 1 },
						} as const,
					];
		const written = await settled(() => batchAcross(conditions, sent, marked));
		if (written.kind === "late" || written.kind === "reused") throw new Unavailable("records");
		if (written.kind === "conflict") continue;
		const afterOf = <T>(was: T | undefined, next: Next<T>) => {
			if (next === undefined) return was;
			return "remove" in next ? undefined : next.value;
		};
		return {
			first: { before: before.first, after: afterOf(before.first, decided.first) },
			second: { before: before.second, after: afterOf(before.second, decided.second) },
		};
	}
	throw new Unavailable("records");
}

/** Records under a name made per space from an unguessable secret; the store never receives it. */
export function secretRecordsIn<T extends Json>(place: Place) {
	claim(place, "secret records");
	const named = recordsOf<T>(place);
	const nameOf = (secret: string) =>
		`1.${createHash("sha256").update(`${place.space.name}\n${secret}`).digest("base64url")}`;
	return {
		nameOf,
		create: (secret: string, value: T, lifetimeMs: number | "endless") =>
			named.create(nameOf(secret), value, lifetimeMs),
		read: (secret: string) => named.read(nameOf(secret)),
		change: (secret: string, change: (current: T) => Changed<T> | undefined) =>
			named.change(nameOf(secret), change),
		remove: (secret: string) => named.remove(nameOf(secret)),
		named,
	};
}

/** Work that must be done later, kept until it is said done. */
export function deferredIn(place: Place & DeferredSize) {
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

export interface Member {
	readonly member: string;
	readonly remainingMs: number;
}

const clearingMs = 10 * 60_000;

export function overCap<T extends readonly [string, number]>(
	byEnd: readonly T[],
	added: string,
	cap: number,
) {
	const over = Math.max(0, byEnd.length - cap);
	const out = new Set(
		byEnd
			.filter(([name]) => name !== added)
			.slice(0, over)
			.map(([name]) => name),
	);
	return { held: byEnd.filter(([name]) => !out.has(name)), out: [...out] };
}

export function checkedCap(cap: number): number {
	if (!Number.isInteger(cap) || cap < 1)
		throw new TypeError("records: a set's cap is a whole number from 1");
	return cap;
}

/** Sets of members by key, at most `cap` to a key, ending on the kernel's clock; what an add pushes out awaits in the same write. */
export function keyedSetsIn(place: Place & { readonly cap: number; readonly clock: Clock }) {
	const cap = checkedCap(place.cap);
	const keyOf = (key: string) => ({ space: place.space, partition: key, name: "set" });
	type Pair = readonly [string, number];
	const isPair = (item: Json): item is Pair =>
		Array.isArray(item) && typeof item[0] === "string" && typeof item[1] === "number";
	const pairsIn = (value: Json | undefined) => (Array.isArray(value) ? value : []).filter(isPair);
	const contentOf = (value: Json | undefined) => {
		if (Array.isArray(value) || typeof value !== "object" || value === null) {
			return { held: pairsIn(value), awaiting: [] as Pair[] };
		}
		const kept = value as { readonly held?: Json; readonly awaiting?: Json };
		return { held: pairsIn(kept.held), awaiting: pairsIn(kept.awaiting) };
	};
	const live = (pairs: readonly Pair[], now: number) => pairs.filter(([, ends]) => ends > now);
	const written = (held: readonly Pair[], awaiting: readonly Pair[], now: number) => {
		const last = Math.max(...held.map(([, end]) => end), ...awaiting.map(([, end]) => end), now);
		return {
			value: { held: [...held], awaiting: [...awaiting] } as Json,
			expiry: { kind: "after" as const, ms: Math.max(1, last - now) + clearingMs },
		};
	};
	const byMember = (pairs: readonly Pair[]) => pairs.map(([member]) => member).sort(codePointOrder);
	return {
		add: async (
			key: string,
			member: string,
			lifetimeMs: number,
		): Promise<{ readonly pushedOut: readonly string[] }> => {
			// The end is fixed at the add, so a write that lands late never shortens it.
			const ends = place.clock.now() + lifetimeMs;
			let pushedOut: string[] = [];
			await rewrite(place, keyOf(key), (current) => {
				const now = place.clock.now();
				const content = contentOf(current);
				const kept = new Map(live(content.held, now));
				kept.set(member, Math.max(kept.get(member) ?? 0, ends));
				const byEnd = [...kept].sort((a, b) => a[1] - b[1] || codePointOrder(a[0], b[0]));
				const { held, out } = overCap(byEnd, member, cap);
				pushedOut = out;
				const awaiting = new Map(live(content.awaiting, now));
				for (const name of out) awaiting.set(name, kept.get(name) ?? now);
				return written(held, [...awaiting], now);
			});
			if (pushedOut.length > 0) {
				place.log?.warn("records.pushed_out", { space: place.space.name, count: pushedOut.length });
			}
			return { pushedOut };
		},
		members: async (key: string): Promise<readonly Member[]> => {
			const { entry } = await place.store.get(keyOf(key));
			const now = place.clock.now();
			return live(contentOf(entry?.value).held, now)
				.map(([member, ends]) => ({ member, remainingMs: ends - now }))
				.sort((a, b) => codePointOrder(a.member, b.member));
		},
		remove: async (key: string, member: string): Promise<void> => {
			await rewrite(place, keyOf(key), (current) => {
				if (current === undefined) return undefined;
				const { held, awaiting } = contentOf(current);
				const now = place.clock.now();
				return written(
					held.filter(([name]) => name !== member),
					live(awaiting, now),
					now,
				);
			});
		},
		awaiting: async (key: string): Promise<readonly string[]> => {
			const { entry } = await place.store.get(keyOf(key));
			return byMember(live(contentOf(entry?.value).awaiting, place.clock.now()));
		},
		settled: async (key: string, member: string): Promise<void> => {
			await rewrite(place, keyOf(key), (current) => {
				if (current === undefined) return undefined;
				const { held, awaiting } = contentOf(current);
				const now = place.clock.now();
				return written(
					held,
					live(awaiting, now).filter(([name]) => name !== member),
					now,
				);
			});
		},
	};
}

export type KeyedSets = ReturnType<typeof keyedSetsIn>;
