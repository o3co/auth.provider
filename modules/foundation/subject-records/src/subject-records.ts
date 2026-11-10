import { type Attempt, type Changed, changeRecords, type Next, type Target } from "@mod/records";
import type { Json } from "@mod/store";
import { kept, opened, ownersValue } from "./envelope/envelope.ts";
import {
	checkedSubjectPlace,
	indexOver,
	listedWith,
	listedWithout,
	type SubjectPlace,
} from "./index/index.ts";

export { eraseSubject, sweepIndex } from "./erase/erase.ts";
export { indexSpaceOf, type Phase, type SubjectPlace } from "./index/index.ts";
export { subjectRecordsPhase } from "./phase/phase.ts";
export { type SubjectKeyedSets, subjectKeyedSetsIn } from "./sets/sets.ts";

/**
 * A subject's records in a space declaring `online-indexed` (its keys in its subject's index),
 * `online-keyed` (its key its subject itself, the index keeping only the tombstone) or `bounded`
 * (written raw, fenced at creation by its subject's tombstone, each gone by its fixed end, at most
 * the space's `boundedMs`); kept in an envelope with the subject once records are indexed,
 * `bounded` aside, and none created past the subject's tombstone. `secret` keys a `bounded` space's
 * records by secrets, as records under a secret are. Every write goes through records'
 * `changeRecords`; reads go to the store, writing nothing. Where the store writes no records of two
 * partitions as one, `index` is not the space's index space, or the space declares no such category,
 * `refuse` (the builder's) is told.
 */
export function subjectRecordsIn<T extends Json>(
	place: SubjectPlace,
	where: string,
	refuse: (where: string, reason: string) => never,
	options: { readonly secret?: true } = {},
) {
	const category = checkedSubjectPlace(
		place,
		["online-indexed", "online-keyed", "bounded"],
		where,
		refuse,
	);
	const bounded = category === "bounded";
	if (options.secret && !bounded) refuse(where, "only a bounded space keys its records by secrets");
	const indexed = place.phase === "indexed";
	// Bounded records are found by no subject, so they are kept raw and indexed by no bucket.
	const enveloped = indexed && !bounded;
	const byKeys = indexed && category === "online-indexed";
	const { tombOf, bucketOf } = indexOver(place, place.space, place.index);
	const recordOf = (key: string): Target =>
		options.secret ? { place, secret: key } : { place, key };
	const open = (held: Json | undefined) => opened(held, enveloped);
	const isRecord = (key: string) => (e: { key: string; name: string }) =>
		e.key === key && e.name === "record";
	/** A lifetime a bounded record may be created with: a number of ms, at most the space's ceiling. */
	const boundedLifetime = (lifetimeMs: number | "endless") => {
		const ceiling = place.space.boundedMs ?? 0;
		if (lifetimeMs === "endless" || !(lifetimeMs >= 1 && lifetimeMs <= ceiling)) {
			throw new TypeError(
				`subject-records: a bounded record lives from 1 ms to ${ceiling} ms (${place.space.name})`,
			);
		}
		return lifetimeMs;
	};
	return {
		/**
		 * Places the record, unless the key holds one (`exists`) or, once indexed, its subject is
		 * erased (`erased`): an owner takes that as refused, never as `exists`. Its value may be made
		 * from the attempt's deadline, as subject-revocation makes a boundary.
		 */
		create: async (
			key: string,
			subject: string,
			value: T | ((attempt: Attempt) => T),
			lifetimeMs: number | "endless",
		): Promise<"created" | "exists" | "erased"> => {
			const lifetime = bounded ? boundedLifetime(lifetimeMs) : lifetimeMs;
			if (category === "online-keyed" && key !== subject) {
				throw new TypeError("subject-records: an online-keyed record is keyed by its subject");
			}
			let answer: "created" | "exists" | "erased" = "created";
			await changeRecords({
				targets: byKeys ? [recordOf(key), bucketOf(subject, key)] : [recordOf(key)],
				watch: () => (indexed ? [tombOf(subject)] : []),
				decide: ([held, bucket], [tomb], attempt) => {
					if (tomb !== undefined) {
						answer = "erased";
						return {};
					}
					if (held !== undefined) {
						answer = "exists";
						return {};
					}
					answer = "created";
					const made = ownersValue(typeof value === "function" ? value(attempt) : value);
					const record: Next<Json> = {
						value: enveloped ? kept(made, subject) : made,
						lifetimeMs: lifetime,
					};
					if (!byKeys) return { targets: [record] };
					return { targets: [record, listedWith(bucket, { key, name: "record" })] };
				},
			});
			return answer;
		},
		read: async (key: string): Promise<T | undefined> => {
			const { entry } = await place.store.get(changeRecords.keyOf(recordOf(key)));
			return open(entry?.value).value as T | undefined;
		},
		/**
		 * Changes the record from what it holds, as records do, leaving its index as it is: its
		 * subject's tombstone absent, where its envelope names one, and nothing where it stopped it.
		 * A bounded record keeps its fixed end, whatever lifetime is given; its subject is not kept, so
		 * no tombstone holds its change. A record kept raw, from before records were indexed, is
		 * changed raw: records turn indexed only under the maintenance key, and the one migration
		 * indexes or removes every raw record before a tombstone can be written (account erasure
		 * §3.3, §5.1).
		 */
		change: async (
			key: string,
			change: (current: T, attempt: Attempt) => Changed<T> | undefined,
		): Promise<{ readonly before: T; readonly after: T } | undefined> => {
			let answer: { readonly before: T; readonly after: T } | undefined;
			await changeRecords({
				targets: [recordOf(key)],
				watch: ([held]) => {
					const { subject } = open(held);
					return subject !== undefined ? [tombOf(subject)] : [];
				},
				decide: ([held], [tomb], attempt) => {
					const found = open(held);
					if (held === undefined || tomb !== undefined) {
						answer = undefined;
						return {};
					}
					const before = found.value as T;
					const changed = change(before, attempt);
					answer = { before, after: changed ? changed.value : before };
					if (!changed) return {};
					const value = kept(ownersValue(changed.value), found.subject);
					const keepsEnd = bounded || changed.lifetimeMs === undefined;
					return { targets: [keepsEnd ? { value } : { value, lifetimeMs: changed.lifetimeMs }] };
				},
			});
			return answer;
		},
		/**
		 * Removes the record, and its entry from its subject's bucket as one; a set under the key
		 * keeps its own. No tombstone stops it.
		 */
		remove: async (key: string): Promise<void> => {
			await changeRecords({
				targets: [recordOf(key)],
				watch: ([held]) => {
					const { subject } = open(held);
					return subject !== undefined && byKeys ? [bucketOf(subject, key)] : [];
				},
				decide: ([held], [bucket]) => {
					if (held === undefined) return {};
					const { subject } = open(held);
					if (subject === undefined || !byKeys) return { targets: [{ remove: true }] };
					return {
						targets: [{ remove: true }],
						watched: [listedWithout(bucket, isRecord(key))],
					};
				},
			});
		},
		/**
		 * Moves the record from one subject to another as one (account erasure §3.5): its envelope's
		 * subject rewritten, its entry out of `from`'s bucket and into `to`'s, held by both subjects'
		 * tombstones absent; a set under the key stays its own subject's. `missing` where there is no
		 * record, `not-from` where its subject is another, `erased` where either tombstone stopped it.
		 * Only an indexed `online-indexed` space.
		 */
		move: async (
			key: string,
			from: string,
			to: string,
		): Promise<"moved" | "missing" | "not-from" | "erased"> => {
			if (!byKeys)
				throw new Error("subject-records: a record moves in an indexed online-indexed space");
			let answer: "moved" | "missing" | "not-from" | "erased" = "moved";
			await changeRecords({
				targets: [recordOf(key), bucketOf(from, key), bucketOf(to, key)],
				watch: () => [tombOf(from), tombOf(to)],
				decide: ([held, fromBucket, toBucket], [fromTomb, toTomb]) => {
					const found = open(held);
					if (held === undefined) answer = "missing";
					else if (found.subject !== from) answer = "not-from";
					else if (fromTomb !== undefined || toTomb !== undefined) answer = "erased";
					else answer = "moved";
					if (answer !== "moved") return {};
					return {
						targets: [
							{ value: kept(found.value as Json, to) },
							listedWithout(fromBucket, isRecord(key)),
							listedWith(toBucket, { key, name: "record" }),
						],
					};
				},
			});
			return answer;
		},
		/** A page of the keys of the space's living records, as `store` walks: names, where keyed by secrets. */
		scan: async (
			cursor?: string,
		): Promise<{ readonly keys: string[]; readonly cursor?: string }> => {
			const name = changeRecords.keyOf({ place, key: "" }).name;
			const page = await place.store.scan(place.space, cursor);
			const keys = page.keys.filter((k) => k.name === name).map((k) => k.partition);
			return page.cursor === undefined ? { keys } : { keys, cursor: page.cursor };
		},
	};
}

/** Records of subjects in one space, as `subjectRecordsIn` builds them. */
export type SubjectRecords<T extends Json> = ReturnType<typeof subjectRecordsIn<T>>;
