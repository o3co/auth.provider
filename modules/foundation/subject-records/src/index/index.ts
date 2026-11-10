import { createHash } from "node:crypto";
import { changesTogether, type Next, type Place, type Target } from "@mod/records";
import { codePointOrder, type Json, type Space } from "@mod/store";

/** The space a space of subjects' records keeps its subjects' index in: `.index` after its name, its guarantees, records' own. */
export function indexSpaceOf(space: Space): Space {
	return { name: `${space.name}.index`, guarantees: space.guarantees, subjectData: "internal" };
}

/** Whether `index` is the index space of `space`: its name, its guarantees as a set, and internal. */
export const isIndexSpaceOf = (index: Space, space: Space) => {
	const set = (s: Space) => JSON.stringify([...new Set(s.guarantees)].sort());
	return (
		index.name === indexSpaceOf(space).name &&
		set(index) === set(space) &&
		index.subjectData === "internal"
	);
};

/** One entry of a bucket: a key, and which of its names it lists, the record or the keyed set. */
export interface Entry {
	readonly key: string;
	readonly name: "record" | "set";
}

/** A bucket's entries: `[key, name]` pairs, sorted; anything else is no entry. */
export const entriesIn = (value: Json | undefined): Entry[] =>
	Array.isArray(value)
		? value.flatMap((e): Entry[] =>
				Array.isArray(e) &&
				e.length === 2 &&
				typeof e[0] === "string" &&
				(e[1] === "record" || e[1] === "set")
					? [{ key: e[0], name: e[1] }]
					: [],
			)
		: [];

const order = (a: Entry, b: Entry) =>
	codePointOrder(a.key, b.key) || codePointOrder(a.name, b.name);
const stored = (entries: readonly Entry[]): Next<Json> =>
	entries.length === 0
		? { remove: true }
		: { value: [...entries].sort(order).map((e) => [e.key, e.name]), lifetimeMs: "endless" };

/** A bucket's next, `entry` listed in it; nothing where it is listed already. */
export const listedWith = (bucket: Json | undefined, entry: Entry): Next<Json> => {
	const entries = entriesIn(bucket);
	const listed = entries.some((e) => e.key === entry.key && e.name === entry.name);
	return listed ? undefined : stored([...entries, entry]);
};

/** A bucket's next without the entries `leaving` picks: nothing where none leaves, removed with its last. */
export const listedWithout = (
	bucket: Json | undefined,
	leaving: (e: Entry) => boolean,
): Next<Json> => {
	const entries = entriesIn(bucket);
	const rest = entries.filter((e) => !leaving(e));
	return rest.length === entries.length ? undefined : stored(rest);
};

/** The target an entry lists, in the space of `place`. */
export const targetOf = (place: Place, entry: Entry): Target =>
	entry.name === "set" ? { place, key: entry.key, set: true } : { place, key: entry.key };

/** The 16 buckets a subject's keys are split over, by the first hex digit of each key's digest. */
export const bucketNames = Array.from({ length: 16 }, (_, i) => `m${i.toString(16)}`);

/**
 * A space's index over `place`'s store: each subject's part of it named by the SHA-256 of the
 * space's name, a line feed and the subject, so no key holds a subject; in it, the subject's
 * tombstone and its buckets, each a record of the index space.
 */
export function indexOver(place: Place, space: Space, index: Space) {
	const indexPlace: Place = {
		store: place.store,
		space: index,
		random: place.random,
		...(place.log ? { log: place.log } : {}),
	};
	const subjects = (subject: string) =>
		`1.${createHash("sha256").update(`${space.name}\n${subject}`).digest("base64url")}`;
	return {
		tombOf: (subject: string): Target => ({ place: indexPlace, key: `${subjects(subject)}.tomb` }),
		bucketOf: (subject: string, key: string): Target => ({
			place: indexPlace,
			key: `${subjects(subject)}.m${createHash("sha256").update(key).digest("hex")[0]}`,
		}),
		/** An entry of the index by its partition, as a scan of the index space finds it. */
		entryAt: (partition: string): Target => ({ place: indexPlace, key: partition }),
		/** Every bucket of a subject, as erasing it reads them. */
		bucketsOf: (subject: string): Target[] =>
			bucketNames.map((name) => ({ place: indexPlace, key: `${subjects(subject)}.${name}` })),
	};
}

/** Whether records are only read as they were (`reader`) or kept indexed by their subject (`indexed`). */
export type Phase = "reader" | "indexed";

/** A place of a space holding subjects' data, with its index space and the phase records are in. */
export interface SubjectPlace extends Place {
	readonly index: Space;
	readonly phase: Phase;
}

/** The checks every builder makes at build: a batch across, the space's own index, a category it writes. */
export function checkedSubjectPlace(
	place: SubjectPlace,
	categories: readonly string[],
	where: string,
	refuse: (where: string, reason: string) => never,
) {
	const category = place.space.subjectData;
	if (!changesTogether(place.store)) {
		refuse(where, "its store writes no records of two partitions as one");
	}
	if (category === undefined || !categories.includes(category)) {
		refuse(where, `its space declares no category it writes (${category ?? "none"})`);
	}
	if (!isIndexSpaceOf(place.index, place.space)) {
		refuse(where, `its index is not ${indexSpaceOf(place.space).name}, of its guarantees`);
	}
	return category as string;
}
