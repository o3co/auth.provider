import type { Attempt, Changed, Next, Target } from "@mod/records";
import type { Json } from "@mod/store";
import { kept, opened, ownersValue } from "../envelope/envelope.ts";
import {
	indexOver,
	listedWith,
	listedWithout,
	type SubjectPlace,
	witnessed,
} from "../index/index.ts";

/**
 * One write's rule for one record: the records of the index it reads besides the record (named
 * from the record as read), and what it answers and writes from all it read. A rule is pure: a
 * race makes the change read all again and the rule decide again.
 */
export interface Rule<A> {
	readonly needs: (held: Json | undefined) => readonly Target[];
	readonly decide: (
		held: Json | undefined,
		needed: readonly (Json | undefined)[],
		attempt: Attempt,
	) => {
		readonly answer: A;
		readonly record?: Next<Json>;
		readonly needed?: readonly Next<Json>[];
	};
}

/** What a change came to: changed (its value before and after), or not, and why. */
export type ChangeAnswer<T> =
	| { readonly kind: "changed"; readonly before: T; readonly after: T }
	| { readonly kind: "missing" }
	| { readonly kind: "erased" };

/**
 * The rules of a place's writes, the one statement of them: what each holds and writes by the
 * category its space declares and the phase, for `writes`' builder and `joint` alike.
 */
export function rulesOf(place: SubjectPlace, category: string) {
	const bounded = category === "bounded";
	const indexed = place.phase === "indexed";
	// Bounded records are found by no subject, so they are kept raw and indexed by no bucket.
	const enveloped = indexed && !bounded;
	const byKeys = indexed && category === "online-indexed";
	// An envelope keyed by its subject is written with its witness, which no raw value has.
	const witnessing = enveloped && category === "online-keyed";
	const { tombOf, bucketOf, witnessOf } = indexOver(place, place.space, place.index);
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
	/**
	 * Moves the record from `from`, the subject it was read under, to `to` as one: its envelope's
	 * subject and value rewritten, its entry out of `from`'s bucket and into `to`'s, held by both
	 * tombstones absent: `erased` where `to`'s stands, `from-erased` where only `from`'s does.
	 * Indexed `online-indexed` only: `moveTo`'s first case, the one caller.
	 */
	const move = (
		key: string,
		from: string,
		to: string,
		value: Json,
	): Rule<"moved" | "missing" | "erased" | "from-erased"> => {
		return {
			needs: () => [bucketOf(from, key), bucketOf(to, key), tombOf(from), tombOf(to)],
			decide: (held, [fromBucket, toBucket, fromTomb, toTomb]) => {
				if (held === undefined) return { answer: "missing" };
				if (toTomb !== undefined) return { answer: "erased" };
				if (fromTomb !== undefined) return { answer: "from-erased" };
				return {
					answer: "moved",
					record: { value: kept(ownersValue(value), to) },
					needed: [
						listedWithout(fromBucket, place.space.name, isRecord(key)),
						listedWith(toBucket, place.space.name, { key, name: "record" }),
						undefined,
						undefined,
					],
				};
			},
		};
	};
	const base = {
		indexed,
		open,
		/** Places the record unless it is held (`exists`) or, once indexed, its subject's tombstone stands (`erased`). */
		create: <T extends Json>(
			key: string,
			value: T | ((attempt: Attempt) => T),
			lifetimeMs: number | "endless",
			subject: string,
		): Rule<"created" | "exists" | "erased"> => {
			const lifetime = bounded ? boundedLifetime(lifetimeMs) : lifetimeMs;
			if (category === "online-keyed" && key !== subject) {
				throw new TypeError("subject-records: an online-keyed record is keyed by its subject");
			}
			const index = byKeys
				? [bucketOf(subject, key)]
				: witnessing
					? [witnessOf(subject, "record")]
					: [];
			return {
				needs: () => [...index, ...(indexed ? [tombOf(subject)] : [])],
				decide: (held, needed, attempt) => {
					const [entry, tomb] = index.length > 0 ? needed : [undefined, needed[0]];
					if (tomb !== undefined) return { answer: "erased" };
					if (held !== undefined) return { answer: "exists" };
					const made = ownersValue(typeof value === "function" ? value(attempt) : value);
					const record: Next<Json> = {
						value: enveloped ? kept(made, subject) : made,
						lifetimeMs: lifetime,
					};
					if (witnessing)
						return {
							answer: "created",
							record,
							needed: [entry === undefined ? witnessed : undefined],
						};
					if (!byKeys) return { answer: "created", record };
					return {
						answer: "created",
						record,
						needed: [listedWith(entry, place.space.name, { key, name: "record" })],
					};
				},
			};
		},
		/**
		 * Changes the record from what it holds, leaving its index as it is: held, and its subject's
		 * tombstone absent where its envelope names one. A bounded record keeps its fixed end.
		 */
		change: <T extends Json>(
			change: (current: T, attempt: Attempt) => Changed<T> | undefined,
		): Rule<ChangeAnswer<T>> => ({
			needs: (held) => {
				const { subject } = open(held);
				if (subject === undefined) return [];
				return witnessing ? [tombOf(subject), witnessOf(subject, "record")] : [tombOf(subject)];
			},
			decide: (held, [tomb, witness], attempt) => {
				const found = open(held);
				if (held === undefined) return { answer: { kind: "missing" } };
				if (tomb !== undefined) return { answer: { kind: "erased" } };
				const before = found.value as T;
				const changed = change(before, attempt);
				const answer = {
					kind: "changed" as const,
					before,
					after: changed ? changed.value : before,
				};
				if (!changed) return { answer };
				const value = kept(ownersValue(changed.value), found.subject);
				const keepsEnd = bounded || changed.lifetimeMs === undefined;
				const record = keepsEnd ? { value } : { value, lifetimeMs: changed.lifetimeMs };
				// An envelope rewritten keyed by its subject has its witness, written where it is missing.
				if (!witnessing || found.subject === undefined) return { answer, record };
				return {
					answer,
					record,
					needed: [undefined, witness === undefined ? witnessed : undefined],
				};
			},
		}),
		/** Removes the record, and its entry from its subject's bucket as one; `when` checks its value in the same change. */
		remove: <T extends Json>(
			key: string,
			when?: (value: T) => boolean,
		): Rule<"removed" | "left" | "missing"> => ({
			needs: (held) => {
				const { subject } = open(held);
				return subject !== undefined && byKeys ? [bucketOf(subject, key)] : [];
			},
			decide: (held, [bucket]) => {
				const found = open(held);
				if (held === undefined) return { answer: "missing" };
				if (when !== undefined && !when(found.value as T)) return { answer: "left" };
				if (found.subject === undefined || !byKeys)
					return { answer: "removed", record: { remove: true } };
				return {
					answer: "removed",
					record: { remove: true },
					needed: [listedWithout(bucket, place.space.name, isRecord(key))],
				};
			},
		}),
	};
	return {
		...base,
		/**
		 * Gives the record to `to` with `value`, from the subject it is read under, in one of three
		 * cases: under another subject, as `move` does; under `to` already, a `change`; kept raw
		 * (`reader`, or before the migration), a `change` too, raw, its new value read by the migration.
		 * `moved` for each, else `missing`, `erased` or `from-erased`, as `change` and `move` answer.
		 */
		moveTo: (
			key: string,
			to: string,
			value: Json,
		): Rule<"moved" | "missing" | "erased" | "from-erased"> => {
			const changing = base.change<Json>(() => ({ value }));
			/** The move a record read under another subject takes; none where it is a change. */
			const moving = (held: Json | undefined) => {
				const { subject } = open(held);
				if (held === undefined || subject === undefined || subject === to || !byKeys)
					return undefined;
				return move(key, subject, to, value);
			};
			return {
				needs: (held) => (moving(held) ?? changing).needs(held),
				decide: (held, needed, attempt) => {
					const move = moving(held);
					if (move) return move.decide(held, needed, attempt);
					const changed = changing.decide(held, needed, attempt);
					const answer =
						changed.answer.kind === "changed" ? ("moved" as const) : changed.answer.kind;
					return { ...changed, answer };
				},
			};
		},
	};
}
