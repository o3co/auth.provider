import { createHash } from "node:crypto";
import {
	BuildRefused,
	type Clock,
	isUnavailable,
	type Log,
	type Random,
	Unavailable,
} from "@mod/kernel";
import {
	type BatchWrite,
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
/** The first pause before a resend, doubled after each, up to the longest. */
const firstPauseMs = 50;
const longestPauseMs = 1000;
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Sends one write until the store answers. Each resend is the same request under the same mark,
 * so a write whose answer was lost gets the answer it first had and never takes effect twice.
 * Patience is counted in pauses, so no clock is read.
 */
async function untilAnswered<A>(send: () => Promise<A>): Promise<A> {
	let waited = 0;
	let wait = firstPauseMs;
	for (;;) {
		try {
			return await send();
		} catch (error) {
			if (!isUnavailable(error) || waited + wait > patienceMs) throw error;
		}
		await pause(wait);
		waited += wait;
		wait = Math.min(wait * 2, longestPauseMs);
	}
}

/** What an attempt answers where it lost a race, or found nothing it could confirm: try again. */
const again = Symbol("again");

/** Runs `attempt` until it answers anything but `again`, at most `attempts` times; past them, unavailable. */
async function retried<A>(attempt: () => Promise<A | typeof again>): Promise<A> {
	for (let tried = 0; tried < attempts; tried++) {
		const answered = await attempt();
		if (answered !== again) return answered;
	}
	throw new Unavailable("records");
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
	const confirmed = await untilAnswered(() =>
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
	return retried(async () => {
		const { entry, now } = await place.store.get(key);
		const before = entry?.value;
		const decided = decide(before);
		if (!decided) {
			if (await confirmedAsRead(place, key, entry?.version, deadlineFrom(now))) {
				return { before, after: before };
			}
			return again;
		}
		const options: WriteOptions = { expiry: decided.expiry, ...markedAt(place, now) };
		const written = entry
			? await untilAnswered(() => place.store.replaceIf(key, entry.version, decided.value, options))
			: await untilAnswered(() => place.store.putIfAbsent(key, decided.value, options));
		if (written.kind === "written") return { before, after: decided.value };
		if (written.kind === "late" || written.kind === "reused") throw new Unavailable("records");
		return again;
	});
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
		// A refusal of the boot, named by the space, so the operator reads why.
		throw new BuildRefused(place.space.name, "a space holds records or secret records, not both");
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
		): Promise<"created" | "exists"> =>
			retried(async () => {
				const marked = markedAt(place, await place.store.now());
				const options: WriteOptions = {
					expiry: lifetimeMs === "endless" ? { kind: "never" } : { kind: "after", ms: lifetimeMs },
					...marked,
				};
				const written = await untilAnswered(() =>
					place.store.putIfAbsent(keyOf(key), value, options),
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

/** Whether two spaces declare the same guarantees, compared as sets, as a batch across them asks. */
const sameGuarantees = (a: Place["space"], b: Place["space"]) => {
	const set = (space: Place["space"]) => JSON.stringify([...new Set(space.guarantees)].sort());
	return set(a) === set(b);
};

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

/** What one record held before a change of records as one, and holds after. */
export interface ChangedRecord<T = Json> {
	readonly before: T | undefined;
	readonly after: T | undefined;
}

/**
 * Changes records as one: the targets, and the records `watch` names from what they hold. `decide`
 * runs on what was read and answers the next of each, by naming (the targets', then the watched
 * ones'); everything read is held by a condition of the one write, so another writer of any of them
 * first makes it read all again, `watch` too, and decide again; it must be pure. A record named
 * twice is read once, held once, and written from one naming at most. Every place is on one store
 * that writes as one (`changesTogether`); the records sit in spaces of one guarantee.
 */
export async function changeRecords(p: {
	readonly targets: readonly Target[];
	readonly watch?: (read: readonly (Json | undefined)[]) => readonly Target[];
	readonly decide: (
		read: readonly (Json | undefined)[],
		watched: readonly (Json | undefined)[],
	) => { readonly targets?: readonly Next<Json>[]; readonly watched?: readonly Next<Json>[] };
}): Promise<{
	readonly targets: readonly ChangedRecord[];
	readonly watched: readonly ChangedRecord[];
}> {
	const [anchor] = p.targets;
	if (!anchor) throw new Error("records changed together name one at least");
	const target = anchor.place.store;
	const batchAcross = target.batchAcross?.bind(target);
	if (!batchAcross) throw new Error("the store writes no records of two partitions as one");
	const checked = (named: Target) => {
		if (named.place.store !== target) throw new Error("records changed together share one store");
		claim(named.place, "records");
	};
	p.targets.forEach((named, at) => {
		checked(named);
		if (p.targets.slice(0, at).some((earlier) => sameTarget(earlier, named))) {
			throw new Error("records changed together are named once each");
		}
	});
	return retried(async () => {
		const marked = markedAt(anchor.place, await target.now());
		// Each record held once: the targets, then what the watch names besides.
		const held: { target: Target; version: string | undefined; value: Json | undefined }[] =
			await Promise.all(
				p.targets.map(async (named) => {
					const { entry } = await target.get(recordKey(named));
					return { target: named, version: entry?.version, value: entry?.value };
				}),
			);
		const read = held.map((h) => h.value);
		const named = p.watch?.(read) ?? [];
		for (const watched of named) {
			checked(watched);
			if (held.some((h) => sameTarget(h.target, watched))) continue;
			const { entry } = await target.get(recordKey(watched));
			held.push({ target: watched, version: entry?.version, value: entry?.value });
		}
		const watchedAt = named.map((w) => held.findIndex((h) => sameTarget(h.target, w)));
		const decided = p.decide(
			read,
			watchedAt.map((at) => held[at]?.value),
		);
		const nexts: Next<Json>[] = held.map(() => undefined);
		const set = (at: number, next: Next<Json>) => {
			if (next === undefined) return;
			if (nexts[at] !== undefined) throw new Error("a record changed together is written once");
			nexts[at] = next;
		};
		for (const [at] of p.targets.entries()) set(at, decided.targets?.[at]);
		for (const [n, at] of watchedAt.entries()) set(at, decided.watched?.[n]);
		const conditions = held.map((h) =>
			h.version === undefined
				? { key: recordKey(h.target), absent: true as const }
				: { key: recordKey(h.target), version: h.version },
		);
		const writes = held.flatMap((h, at): BatchWrite[] => {
			const next = nexts[at];
			if (next === undefined) return [];
			if ("remove" in next) return [{ key: recordKey(h.target), remove: true as const }];
			return [{ key: recordKey(h.target), put: next.value, expiry: expiryOf(next.lifetimeMs) }];
		});
		// Nothing to write: what was read is confirmed by a mark of its own, held by the same conditions.
		const sent =
			writes.length > 0
				? writes
				: [
						{
							key: { ...recordKey(anchor), name: "settled" },
							put: true,
							expiry: { kind: "after", ms: 1 },
						} as const,
					];
		const written = await untilAnswered(() => batchAcross(conditions, sent, marked));
		if (written.kind === "late" || written.kind === "reused") throw new Unavailable("records");
		if (written.kind === "conflict") return again;
		const changedAt = (at: number): ChangedRecord => {
			const was = held[at]?.value;
			const next = nexts[at];
			if (next === undefined) return { before: was, after: was };
			return { before: was, after: "remove" in next ? undefined : next.value };
		};
		return {
			targets: p.targets.map((_, at) => changedAt(at)),
			watched: watchedAt.map(changedAt),
		};
	});
}

/**
 * Changes two records as one, from what both hold and what `watch` names besides, as
 * `changeRecords` does; only the two are written. A record `watch` names that is the first or
 * second is read once and held once.
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
	readonly first: ChangedRecord<A>;
	readonly second: ChangedRecord<B>;
}> {
	const { first, second } = p;
	if (!changesTogether(first.place.store)) {
		throw new Error("the store writes no records of two partitions as one");
	}
	if (second.place.store !== first.place.store) {
		throw new Error("records changed together share one store");
	}
	if (sameTarget(first, second)) throw new Error("records changed together are two records");
	const { watch } = p;
	const changed = await changeRecords({
		targets: [first, second],
		...(watch ? { watch: ([a, b]) => watch(a as A | undefined, b as B | undefined) } : {}),
		decide: ([a, b], watched) => {
			const next = p.decide(a as A | undefined, b as B | undefined, watched);
			return { targets: [next.first, next.second] };
		},
	});
	const [a, b] = changed.targets;
	return { first: a as ChangedRecord<A>, second: b as ChangedRecord<B> };
}

/**
 * Records of two places changed as one, by key in each, with the records of either place `watch`
 * names besides, as `changeRecords` does. What is read, and what is decided, is by place: each
 * place's keys, then its watched ones, in order. Where the places' store cannot, `refuse` (the
 * builder's) is told, naming `where`: a wiring then maps it with no branch of its own.
 */
export function pairedRecordsAcross<A extends Json, B extends Json>(
	first: Place,
	second: Place,
	where: string,
	refuse: (where: string, reason: string) => never,
) {
	if (!changesTogether(first.store)) {
		refuse(where, "its store writes no records of two partitions as one");
	}
	// Known at build, so refused at build: the store would refuse every change of them alike.
	if (second.store !== first.store) {
		refuse(where, "its two places are on two stores, which write nothing of both as one");
	}
	if (!sameGuarantees(first.space, second.space)) {
		refuse(
			where,
			"its two spaces declare other guarantees, so a fault could keep one and drop the other",
		);
	}
	claim(first, "records");
	claim(second, "records");
	type Read = {
		readonly first: readonly (A | undefined)[];
		readonly second: readonly (B | undefined)[];
	};
	type Changed = {
		readonly first: readonly ChangedRecord<A>[];
		readonly second: readonly ChangedRecord<B>[];
	};
	return {
		changeRecords: async (
			keys: { readonly first: readonly string[]; readonly second: readonly string[] },
			p: {
				readonly watch?: (read: Read) => {
					readonly first?: readonly string[] | undefined;
					readonly second?: readonly string[] | undefined;
				};
				readonly decide: (read: Read) => {
					readonly first?: readonly Next<A>[] | undefined;
					readonly second?: readonly Next<B>[] | undefined;
				};
			},
		): Promise<Changed> => {
			const fixed = keys.first.length;
			const targets = [
				...keys.first.map((key) => ({ place: first, key })),
				...keys.second.map((key) => ({ place: second, key })),
			];
			// The watch of the attempt deciding: each attempt runs the watch before its decision.
			let watched = { first: [] as readonly string[], second: [] as readonly string[] };
			/** What is read, or what came of it, by place: each place's keys, then its watched ones. */
			const byPlace = <F, S>(fixedOnes: readonly unknown[], watchedOnes: readonly unknown[]) => ({
				first: [
					...fixedOnes.slice(0, fixed),
					...watchedOnes.slice(0, watched.first.length),
				] as readonly F[],
				second: [
					...fixedOnes.slice(fixed),
					...watchedOnes.slice(watched.first.length),
				] as readonly S[],
			});
			/** `length` of `ones`, from `from`: a place's decided changes for its keys, or its watched ones. */
			const take = (ones: readonly Next<Json>[], from: number, length: number) =>
				Array.from({ length }, (_, at) => ones[from + at]);
			const changed = await changeRecords({
				targets,
				watch: (read) => {
					const named = p.watch?.(byPlace<A | undefined, B | undefined>(read, [])) ?? {};
					watched = { first: named.first ?? [], second: named.second ?? [] };
					return [
						...watched.first.map((key) => ({ place: first, key })),
						...watched.second.map((key) => ({ place: second, key })),
					];
				},
				decide: (read, found) => {
					const next = p.decide(byPlace<A | undefined, B | undefined>(read, found));
					const ofFirst: readonly Next<Json>[] = next.first ?? [];
					const ofSecond: readonly Next<Json>[] = next.second ?? [];
					const fixedSecond = keys.second.length;
					return {
						targets: [...take(ofFirst, 0, fixed), ...take(ofSecond, 0, fixedSecond)],
						watched: [
							...take(ofFirst, fixed, watched.first.length),
							...take(ofSecond, fixedSecond, watched.second.length),
						],
					};
				},
			});
			return byPlace<ChangedRecord<A>, ChangedRecord<B>>(changed.targets, changed.watched);
		},
	};
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
