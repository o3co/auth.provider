import { type Attempt, type Changed, changeRecords, type Target } from "@mod/records";
import type { Json } from "@mod/store";
import { checkedSubjectPlace, type SubjectPlace } from "../index/index.ts";
import { type Rule, rulesOf } from "./rules.ts";

/**
 * A subject's records in a space declaring `online-indexed` (its keys in its subject's index),
 * `online-keyed` (its key its subject itself, the index keeping its tombstone and, once indexed, the
 * witness of its envelope) or `bounded` (written raw, fenced at creation by its subject's tombstone,
 * each gone by its fixed end, at most the space's `boundedMs`); kept in an envelope with the subject
 * once records are indexed, `bounded` aside, and none created past the subject's tombstone. `secret`
 * keys a `bounded` space's records by secrets, as records under a secret are. Every write goes
 * through records' `changeRecords`; reads go to the store, writing nothing. Where, once indexed, the
 * store writes no records of two partitions as one, or where `index` is not the space's index space
 * or the space declares no such category, `refuse` (the builder's) is told.
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
	const rules = rulesOf(place, category);
	const recordOf = (key: string): Target =>
		options.secret ? { place, secret: key } : { place, key };
	/** Runs one rule on one record, as one change: its needs read beside it, its writes in one write. */
	const ruled = async <A>(key: string, rule: Rule<A>): Promise<A> => {
		let answer: A | undefined;
		await changeRecords({
			targets: [recordOf(key)],
			watch: ([held]) => rule.needs(held),
			decide: ([held], needed, attempt) => {
				const decided = rule.decide(held, needed, attempt);
				answer = decided.answer;
				return {
					...(decided.record === undefined ? {} : { targets: [decided.record] }),
					...(decided.needed === undefined ? {} : { watched: decided.needed }),
				};
			},
		});
		return answer as A;
	};
	return {
		/**
		 * Places the record, unless the key holds one (`exists`) or, once indexed, its subject is
		 * erased (`erased`): an owner takes that as refused, never as `exists`. Its value may be made
		 * from the attempt's deadline, as subject-revocation makes a boundary.
		 */
		create: async (
			key: string,
			value: T | ((attempt: Attempt) => T),
			lifetimeMs: number | "endless",
			subject: string,
		): Promise<"created" | "exists" | "erased"> =>
			ruled(key, rules.create(key, value, lifetimeMs, subject)),
		/**
		 * Saves a record that holds no subject's data, raw, in an `online-*` space, unless the key holds
		 * one (`exists`); `closed` once this builder's phase is `indexed`, where no raw record is
		 * written: the owner keeps such records elsewhere then. The phase is the one the builder was
		 * built with (`phased`'s `once`); a writer whose phase is stale is stopped by the maintenance
		 * window's fence, epoch and restarts (account erasure §5.1). Its records read as orphans to
		 * the one migration, through the owner's `Elsewhere`. It has no read, removal or scan of its
		 * own: the builder's `read`, `change` and `remove` reach them.
		 * @deprecated Raw records of a space from before its non-subject records moved out; removed in
		 * 0.22.
		 */
		unowned: async (
			key: string,
			value: Json,
			lifetimeMs: number | "endless",
		): Promise<"created" | "exists" | "closed"> => {
			if (bounded) throw new TypeError("subject-records: a bounded space keeps no unowned record");
			if (rules.indexed) return "closed";
			let answer: "created" | "exists" | "closed" = "created";
			await changeRecords({
				targets: [recordOf(key)],
				decide: ([held]) => {
					answer = held === undefined ? "created" : "exists";
					return held === undefined ? { targets: [{ value, lifetimeMs }] } : {};
				},
			});
			return answer;
		},
		read: async (key: string): Promise<T | undefined> => {
			const { entry } = await place.store.get(changeRecords.keyOf(recordOf(key)));
			return rules.open(entry?.value).value as T | undefined;
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
			const answer = await ruled(key, rules.change(change));
			return answer.kind === "changed" ? { before: answer.before, after: answer.after } : undefined;
		},
		/**
		 * Removes the record, and its entry from its subject's bucket as one; a set under the key
		 * keeps its own. No tombstone stops it. Where `when` is given, only a record whose value, raw
		 * or opened from its envelope, it answers true for: checked in the same change that removes,
		 * so the record removed is the one checked. `removed`, `left` (`when` said no) or `missing`.
		 */
		remove: async (
			key: string,
			when?: (value: T) => boolean,
		): Promise<"removed" | "left" | "missing"> => ruled(key, rules.remove(key, when)),
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
			// Either tombstone stops it, as this one op has always answered.
			const moved = await ruled(key, rules.move(key, from, to));
			return moved === "from-erased" ? "erased" : moved;
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
