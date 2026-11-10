import { createHash } from "node:crypto";
import {
	type Attempt,
	type Changed,
	changeRecords,
	changesTogether,
	type Next,
	type Place,
	type Target,
} from "@mod/records";
import { codePointOrder, type Json, type Space } from "@mod/store";
import { kept, opened, ownersValue } from "./envelope/envelope.ts";

/** The space a space of subjects' records keeps its subjects' index in: `.index` after its name, its guarantees, records' own. */
export function indexSpaceOf(space: Space): Space {
	return { name: `${space.name}.index`, guarantees: space.guarantees, subjectData: "internal" };
}

/** Whether `index` is the index space of `space`: its name, its guarantees as a set, and internal. */
const isIndexSpaceOf = (index: Space, space: Space) => {
	const set = (s: Space) => JSON.stringify([...new Set(s.guarantees)].sort());
	return (
		index.name === indexSpaceOf(space).name &&
		set(index) === set(space) &&
		index.subjectData === "internal"
	);
};

/** Whether records are only read as they were (`reader`) or kept indexed by their subject (`indexed`). */
export type Phase = "reader" | "indexed";

/** A place of a space holding subjects' data, with its index space and the phase records are in. */
export interface SubjectPlace extends Place {
	readonly index: Space;
	readonly phase: Phase;
}

/** The keys of a subject's records, by bucket: a sorted list of strings, nothing else. */
const keysIn = (value: Json | undefined): string[] =>
	Array.isArray(value) ? value.filter((k): k is string => typeof k === "string") : [];

/**
 * A subject's records in a space declaring `online-indexed` (its keys in its subject's index) or
 * `online-keyed` (its key made from its subject alone, the index keeping only the tombstone), kept
 * in an envelope with the subject once records are indexed, and none written past the subject's
 * tombstone. Every write goes through records' `changeRecords`; reads go to the store, writing
 * nothing. Where the store writes no records of two partitions as one, or `index` is not the
 * space's index space, or the space declares no such category, `refuse` (the builder's) is told.
 */
export function subjectRecordsIn<T extends Json>(
	place: SubjectPlace,
	where: string,
	refuse: (where: string, reason: string) => never,
) {
	const category = place.space.subjectData;
	if (!changesTogether(place.store)) {
		refuse(where, "its store writes no records of two partitions as one");
	}
	if (category !== "online-indexed" && category !== "online-keyed") {
		refuse(where, `its space declares no category subject-records writes (${category ?? "none"})`);
	}
	if (!isIndexSpaceOf(place.index, place.space)) {
		refuse(where, `its index is not ${indexSpaceOf(place.space).name}, of its guarantees`);
	}
	const indexed = place.phase === "indexed";
	const byKeys = category === "online-indexed";
	const indexPlace: Place = {
		store: place.store,
		space: place.index,
		random: place.random,
		...(place.log ? { log: place.log } : {}),
	};
	/** A subject's part of the index, named by a digest of the space's name and the subject, so no key holds a subject. */
	const subjects = (subject: string) =>
		`1.${createHash("sha256").update(`${place.space.name}\n${subject}`).digest("base64url")}`;
	const tombOf = (subject: string): Target => ({
		place: indexPlace,
		key: `${subjects(subject)}.tomb`,
	});
	/** The bucket of a key: one of 16, by the first hex digit of the key's digest. */
	const bucketOf = (subject: string, key: string): Target => ({
		place: indexPlace,
		key: `${subjects(subject)}.m${createHash("sha256").update(key).digest("hex")[0]}`,
	});
	const recordOf = (key: string): Target => ({ place, key });
	return {
		/**
		 * Places the record, unless the key holds one (`exists`) or, once indexed, its subject is
		 * erased (`erased`): an owner takes that as refused, never as `exists`.
		 */
		create: async (
			key: string,
			subject: string,
			value: T | ((attempt: Attempt) => T),
			lifetimeMs: number | "endless",
		): Promise<"created" | "exists" | "erased"> => {
			let answer: "created" | "exists" | "erased" = "created";
			const withBucket = indexed && byKeys;
			await changeRecords({
				targets: withBucket ? [recordOf(key), bucketOf(subject, key)] : [recordOf(key)],
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
					const record: Next<Json> = { value: indexed ? kept(made, subject) : made, lifetimeMs };
					if (!withBucket) return { targets: [record] };
					const keys = keysIn(bucket);
					const listed: Next<Json> = keys.includes(key)
						? undefined
						: { value: [...keys, key].sort(codePointOrder), lifetimeMs: "endless" };
					return { targets: [record, listed] };
				},
			});
			return answer;
		},
		read: async (key: string): Promise<T | undefined> => {
			const { entry } = await place.store.get(changeRecords.keyOf(recordOf(key)));
			return opened(entry?.value).value as T | undefined;
		},
		/**
		 * Changes the record from what it holds, as records do, its subject's tombstone absent; its
		 * index is left as it is. Nothing where there is no record, or its subject is erased. A record
		 * kept raw, from before records were indexed, is changed raw: records turn indexed only under
		 * the maintenance key, and the one migration indexes or removes every raw record before a
		 * tombstone can be written (account erasure §3.3, §5.1).
		 */
		change: async (
			key: string,
			change: (current: T, attempt: Attempt) => Changed<T> | undefined,
		): Promise<{ readonly before: T; readonly after: T } | undefined> => {
			let answer: { readonly before: T; readonly after: T } | undefined;
			await changeRecords({
				targets: [recordOf(key)],
				watch: ([held]) => {
					const { subject } = opened(held);
					return indexed && subject !== undefined ? [tombOf(subject)] : [];
				},
				decide: ([held], [tomb], attempt) => {
					const found = opened(held);
					if (held === undefined || tomb !== undefined) {
						answer = undefined;
						return {};
					}
					const before = found.value as T;
					const changed = change(before, attempt);
					answer = { before, after: changed ? changed.value : before };
					if (!changed) return {};
					const value = kept(ownersValue(changed.value), found.subject);
					const lifetime =
						changed.lifetimeMs === undefined ? {} : { lifetimeMs: changed.lifetimeMs };
					return { targets: [{ value, ...lifetime }] };
				},
			});
			return answer;
		},
		/** Removes the record, and its key from its subject's bucket as one; no tombstone stops it. */
		remove: async (key: string): Promise<void> => {
			await changeRecords({
				targets: [recordOf(key)],
				watch: ([held]) => {
					const { subject } = opened(held);
					return subject !== undefined && byKeys ? [bucketOf(subject, key)] : [];
				},
				decide: ([held], [bucket]) => {
					if (held === undefined) return {};
					const { subject } = opened(held);
					if (subject === undefined || !byKeys || bucket === undefined) {
						return { targets: [{ remove: true }] };
					}
					const keys = keysIn(bucket).filter((k) => k !== key);
					const listed: Next<Json> =
						keys.length > 0 ? { value: keys, lifetimeMs: "endless" } : { remove: true };
					return { targets: [{ remove: true }], watched: [listed] };
				},
			});
		},
		/** A page of the keys of the space's living records, as `store` walks. */
		scan: async (
			cursor?: string,
		): Promise<{ readonly keys: string[]; readonly cursor?: string }> => {
			const name = changeRecords.keyOf(recordOf("")).name;
			const page = await place.store.scan(place.space, cursor);
			const keys = page.keys.filter((k) => k.name === name).map((k) => k.partition);
			return page.cursor === undefined ? { keys } : { keys, cursor: page.cursor };
		},
	};
}

/** Records of subjects in one space, as `subjectRecordsIn` builds them. */
export type SubjectRecords<T extends Json> = ReturnType<typeof subjectRecordsIn<T>>;
