import type { Clock } from "@mod/kernel";
import { changeRecords, keyedSetsIn, type Member, type Next, type Target } from "@mod/records";
import type { Json } from "@mod/store";
import { kept, opened } from "../envelope/envelope.ts";
import {
	checkedSubjectPlace,
	indexOver,
	listedWith,
	type SubjectPlace,
	witnessed,
} from "../index/index.ts";

/**
 * Keyed sets in a space holding subjects' data, in the format `records`' keyed sets keep
 * (`keyedSetsIn.codec`) and where they keep them, so processes that only read and the one migration
 * see the same sets: in a space declaring `online-indexed`, each set's key is in its subject's index;
 * in one declaring `online-keyed`, its key is its subject itself. Once records are indexed,
 * a set is kept in an envelope with its subject and no member is added past the subject's tombstone.
 * Where the store writes no records of two partitions as one, `index` is not the space's index
 * space, or the space declares no such category, `refuse` (the builder's) is told.
 */
export function subjectKeyedSetsIn(
	place: SubjectPlace & { readonly cap: number; readonly clock: Clock },
	where: string,
	refuse: (where: string, reason: string) => never,
) {
	const category = checkedSubjectPlace(place, ["online-indexed", "online-keyed"], where, refuse);
	const codec = keyedSetsIn.codec(place);
	const indexed = place.phase === "indexed";
	const byKeys = indexed && category === "online-indexed";
	// A set's envelope keyed by its subject is written with its witness, which no raw value has.
	const witnessing = indexed && category === "online-keyed";
	const { tombOf, bucketOf, witnessOf } = indexOver(place, place.space, place.index);
	const setOf = (key: string): Target => ({ place, key, set: true });
	const open = (held: Json | undefined) => opened(held, indexed);
	const heldValue = async (key: string) =>
		open((await place.store.get(changeRecords.keyOf(setOf(key)))).entry?.value).value;
	/** Rewrites a set as the codec decides on what it holds, in the envelope it was read in. */
	const rewritten = (key: string, decide: (current: Json | undefined) => Next<Json>) =>
		changeRecords({
			targets: [setOf(key)],
			watch: ([held]) => {
				const { subject } = open(held);
				return witnessing && subject !== undefined ? [witnessOf(subject, "set")] : [];
			},
			decide: ([held], [witness]) => {
				if (held === undefined) return {};
				const found = open(held);
				const next = decide(found.value);
				if (next === undefined || "remove" in next) return { targets: [next] };
				const targets = [{ ...next, value: kept(next.value, found.subject) }];
				if (!witnessing || found.subject === undefined) return { targets };
				return { targets, watched: [witness === undefined ? witnessed : undefined] };
			},
		});
	return {
		/**
		 * Adds `member` for `lifetimeMs`, answering those pushed out over the cap. Once indexed,
		 * `erased` where the subject's tombstone stopped it, and `another-subject` where the set is
		 * another subject's, or kept raw in an `online-indexed` space, whose subject none can tell:
		 * an owner takes either as refused. A set never changes subject.
		 */
		add: async (
			key: string,
			member: string,
			lifetimeMs: number,
			subject: string,
		): Promise<{ readonly pushedOut: readonly string[] } | "erased" | "another-subject"> => {
			if (category === "online-keyed" && key !== subject) {
				throw new TypeError("subject-records: an online-keyed set is keyed by its subject");
			}
			// The end is fixed at the add, so a write that lands late never shortens it.
			const ends = place.clock.now() + lifetimeMs;
			let answer = { pushedOut: [] } as
				| { readonly pushedOut: readonly string[] }
				| "erased"
				| "another-subject";
			await changeRecords({
				targets: byKeys
					? [setOf(key), bucketOf(subject, key)]
					: witnessing
						? [setOf(key), witnessOf(subject, "set")]
						: [setOf(key)],
				watch: () => (indexed ? [tombOf(subject)] : []),
				decide: ([held, bucket], [tomb]) => {
					if (tomb !== undefined) {
						answer = "erased";
						return {};
					}
					const found = open(held);
					const claimed = held !== undefined && indexed && found.subject !== subject;
					if (claimed && (found.subject !== undefined || category === "online-indexed")) {
						answer = "another-subject";
						return {};
					}
					const added = codec.add(found.value, member, ends);
					answer = { pushedOut: added.pushedOut };
					const set: Next<Json> = {
						value: indexed ? kept(added.next.value, subject) : added.next.value,
						lifetimeMs: added.next.lifetimeMs,
					};
					if (witnessing) return { targets: [set, bucket === undefined ? witnessed : undefined] };
					if (!byKeys) return { targets: [set] };
					return { targets: [set, listedWith(bucket, place.space.name, { key, name: "set" })] };
				},
			});
			if (typeof answer === "object" && answer.pushedOut.length > 0) {
				place.log?.warn("records.pushed_out", {
					space: place.space.name,
					count: answer.pushedOut.length,
				});
			}
			return answer;
		},
		members: async (key: string): Promise<readonly Member[]> => codec.members(await heldValue(key)),
		/** Removes `member`; no tombstone stops it. */
		remove: async (key: string, member: string): Promise<void> => {
			await rewritten(key, (current) => codec.remove(current, member));
		},
		awaiting: async (key: string): Promise<readonly string[]> =>
			codec.awaiting(await heldValue(key)),
		/** Settles a member pushed out and awaiting; no tombstone stops it. */
		settled: async (key: string, member: string): Promise<void> => {
			await rewritten(key, (current) => codec.settled(current, member));
		},
	};
}

/** Keyed sets of subjects in one space, as `subjectKeyedSetsIn` builds them. */
export type SubjectKeyedSets = ReturnType<typeof subjectKeyedSetsIn>;
