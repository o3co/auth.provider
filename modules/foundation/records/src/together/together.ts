import { Unavailable } from "@mod/kernel";
import type { BatchWrite, Condition, Json, Key, Store, WriteOptions } from "@mod/store";
import {
	type Attempt,
	again,
	type Changed,
	claim,
	expiryOf,
	markedAt,
	nameOf,
	type Place,
	plainDoor,
	retried,
	untilAnswered,
} from "../writing/writing.ts";

/**
 * A record by its place and key, or by its place and the secret it is kept under, where
 * `changeTogether` reads or writes it.
 */
export type Target =
	| { readonly place: Place; readonly key: string; readonly set?: true }
	| { readonly place: Place; readonly secret: string };

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
	plainDoor(place);
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

/** A target's partition: its key, or the name its secret is kept by. */
const partitionOf = (target: Target) =>
	"secret" in target ? nameOf(target.place.space, target.secret) : target.key;
/** Where a target is kept: a keyed set's record (`set`) as keyed sets keep it, any other as records do. */
const recordKey = (target: Target) => ({
	space: target.place.space,
	partition: partitionOf(target),
	name: "set" in target && target.set ? "set" : "record",
});
const sameTarget = (a: Target, b: Target) =>
	a.place.space.name === b.place.space.name &&
	partitionOf(a) === partitionOf(b) &&
	recordKey(a).name === recordKey(b).name;
/** The kind of records a target holds its space to: under a secret, or plain, keyed sets among them. */
const kindOf = (target: Target) => ("secret" in target ? "secret records" : "records");

/** What one record held before a change of records as one, and holds after. */
export interface ChangedRecord<T = Json> {
	readonly before: T | undefined;
	readonly after: T | undefined;
}

/**
 * The write an attempt sends, chosen from the keys it sends alone (conditions and writes, the
 * settled mark among them): the store's `batch` where they share one space and partition, its
 * batch across where they span two. A resend sends the same keys, so it takes the same write.
 */
function writtenBy(target: Store, conditions: readonly Condition[], writes: readonly BatchWrite[]) {
	const keys = [...conditions.map((c) => c.key), ...writes.map((w) => w.key)];
	const one = new Set(keys.map((k) => JSON.stringify([k.space.name, k.partition]))).size === 1;
	if (one)
		return (marked: Omit<WriteOptions, "expiry">) => target.batch(conditions, writes, marked);
	const batchAcross = target.batchAcross?.bind(target);
	if (!batchAcross) throw new Error("the store writes no records of two partitions as one");
	return (marked: Omit<WriteOptions, "expiry">) => batchAcross(conditions, writes, marked);
}

/**
 * Changes records as one: the targets, and the records `watch` names from what they hold. `decide`
 * runs on what was read and answers the next of each, by naming (the targets', then the watched
 * ones'); everything read is held by a condition of the one write, so another writer of any of them
 * first makes it read all again, `watch` too, and decide again; it must be pure. A record named
 * twice is read once, held once, and written from one naming at most. Every place is on one store;
 * an attempt whose keys span two partitions needs one that writes across them (`changesTogether`),
 * one within a partition does not. The records sit in spaces of one guarantee.
 */
export async function changeRecords(p: {
	readonly targets: readonly Target[];
	readonly watch?: (read: readonly (Json | undefined)[]) => readonly Target[];
	/** Handed, as a change is, the deadline its attempt is written with; a retry its own. */
	readonly decide: (
		read: readonly (Json | undefined)[],
		watched: readonly (Json | undefined)[],
		attempt: Attempt,
	) => { readonly targets?: readonly Next<Json>[]; readonly watched?: readonly Next<Json>[] };
}): Promise<{
	readonly targets: readonly ChangedRecord[];
	readonly watched: readonly ChangedRecord[];
}> {
	const [anchor] = p.targets;
	if (!anchor) throw new Error("records changed together name one at least");
	const target = anchor.place.store;
	// A space is named one way in one call: plainly or by secret. A record and a set never share a name.
	const namedAs = new Map<string, "records" | "secret records">();
	const checked = (one: Target) => {
		if (one.place.store !== target) throw new Error("records changed together share one store");
		const kind = kindOf(one);
		if ((namedAs.get(one.place.space.name) ?? kind) !== kind) {
			throw new Error("records changed together name a space one way: plainly or by secret");
		}
		namedAs.set(one.place.space.name, kind);
		// A set's space holds records, as keyedSetsIn claims it.
		claim(one.place, kind);
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
			{ deadline: marked.deadline },
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
		const written = await untilAnswered(() => writtenBy(target, conditions, sent)(marked));
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
 * The store key a target's record is kept under, as `changeRecords` reads and writes it: for
 * subject-records, which reads such records through the store, never writing to read.
 */
changeRecords.keyOf = (target: Target): Key => recordKey(target);

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
	plainDoor(first);
	plainDoor(second);
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
