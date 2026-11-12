import { Unavailable } from "@mod/kernel";
import {
	type Attempt,
	type ChangedRecord,
	changeRecords,
	changesTogether,
	type Next,
	type Target,
} from "@mod/records";
import type { Json } from "@mod/store";
import { checkedSubjectPlace, type SubjectPlace } from "../index/index.ts";
import { type Rule, rulesOf } from "../writes/rules.ts";

/** A record of the joint's places: the place's name in `places`, and its key. */
export interface JointKey<P extends string> {
	readonly place: P;
	readonly key: string;
}

/** A record as a joint change reads it: the owner's value, and its envelope's subject; none, raw. */
export type JointRead = { readonly value: Json; readonly subject?: string } | undefined;

/** What a joint change does to one record. */
export type JointOp =
	/** Places it for `subject`, unless held (`exists`) or the subject's tombstone stands (`erased`). */
	| {
			readonly kind: "create";
			readonly value: Json;
			readonly lifetimeMs: number | "endless";
			readonly subject: string;
	  }
	/** Rewrites it, unless gone (`missing`) or its subject's tombstone stands (`erased`). */
	| { readonly kind: "change"; readonly value: Json; readonly lifetimeMs?: number | "endless" }
	/** Removes it, with its bucket's entry; never refused, a record gone reading undefined before and after. */
	| { readonly kind: "remove" }
	/** Gives it to `to` with `value`, from the subject it is read under (see the card's three cases). */
	| { readonly kind: "move"; readonly value: Json; readonly to: string };

/** Where a refusal is: the target or the watched record, by its place in its list. */
export interface JointAt {
	readonly in: "targets" | "watched";
	readonly index: number;
}

/** A record of a joint change, opened: what it held, and holds after. */
export interface JointChanged {
	readonly before: JointRead;
	readonly after: JointRead;
}

/** A joint change's answer, whole: written as one, or refused at one record, nothing written. */
export type JointAnswer =
	| {
			readonly kind: "written";
			readonly targets: readonly JointChanged[];
			readonly watched: readonly JointChanged[];
	  }
	| {
			readonly kind: "refused";
			readonly at: JointAt;
			readonly why: "exists" | "erased" | "missing";
	  };

type Ruled = Rule<"ok" | "exists" | "erased" | "missing" | "from-erased">;

/** The key every records target is held under, to tell one record from another across namings. */
const idOf = (target: Target) => JSON.stringify(changeRecords.keyOf(target));

/**
 * Records of several `online-indexed` places on one store, changed as one by `changeSubjectRecords`:
 * the owner decides an op for each record it names, and each op holds and writes what `writes`' own
 * rule for it does (its bucket, its subject's tombstone), every subject an op names held in the one
 * write. Refuses at build, through `refuse`: a place of another category, a store writing no records
 * of two partitions as one (in either phase), places on two stores or of differing guarantees.
 */
export function jointRecordsIn<P extends string>(
	places: Readonly<Record<P, SubjectPlace>>,
	where: string,
	refuse: (where: string, reason: string) => never,
) {
	const named = Object.entries(places) as [P, SubjectPlace][];
	const [first] = named;
	if (!first) throw new TypeError("subject-records: a joint change names one place at least");
	for (const [, place] of named) checkedSubjectPlace(place, ["online-indexed"], where, refuse);
	const store = first[1].store;
	if (named.some(([, place]) => place.store !== store)) {
		refuse(where, "a joint change's places are on one store");
	}
	if (!changesTogether(store))
		refuse(where, "its store writes no records of two partitions as one");
	const guarantees = (place: SubjectPlace) =>
		JSON.stringify([...new Set(place.space.guarantees)].sort());
	if (named.some(([, place]) => guarantees(place) !== guarantees(first[1]))) {
		refuse(where, "a joint change's places declare differing guarantees");
	}
	const rules = Object.fromEntries(
		named.map(([name, place]) => [name, rulesOf(place, "online-indexed")]),
	) as Record<P, ReturnType<typeof rulesOf>>;
	const targetOf = ({ place, key }: JointKey<P>): Target => {
		if (!(place in places)) throw new TypeError(`subject-records: no place named ${place}`);
		return { place: places[place], key };
	};
	const opened = (name: P, held: Json | undefined): JointRead => {
		if (held === undefined) return undefined;
		const { value, subject } = rules[name].open(held);
		return subject === undefined ? { value: value as Json } : { value: value as Json, subject };
	};

	/** The rule an op follows on a record read as `held`: `writes`' own, a move's three cases among them. */
	const ruleOf = (name: P, key: string, held: Json | undefined, op: JointOp): Ruled => {
		const rule = rules[name];
		const changed = (value: Json, lifetimeMs?: number | "endless") => {
			const inner = rule.change<Json>(() =>
				lifetimeMs === undefined ? { value } : { value, lifetimeMs },
			);
			return {
				needs: inner.needs,
				decide: (h, needed, attempt) => {
					const d = inner.decide(h, needed, attempt);
					const answer = d.answer.kind === "changed" ? ("ok" as const) : d.answer.kind;
					return { ...d, answer };
				},
			} satisfies Ruled;
		};
		if (op.kind === "create") {
			const inner = rule.create(key, op.value, op.lifetimeMs, op.subject);
			return {
				needs: inner.needs,
				decide: (h, needed, attempt) => {
					const d = inner.decide(h, needed, attempt);
					return { ...d, answer: d.answer === "created" ? "ok" : d.answer };
				},
			};
		}
		if (op.kind === "change") return changed(op.value, op.lifetimeMs);
		if (op.kind === "remove") {
			const inner = rule.remove(key);
			return {
				needs: inner.needs,
				// A record gone is removed already: no refusal.
				decide: (h, needed, attempt) => ({ ...inner.decide(h, needed, attempt), answer: "ok" }),
			};
		}
		// A move from the subject it is read under: raw, or under `to` already, it is a change.
		const from = rule.open(held).subject;
		if (held === undefined || from === undefined || from === op.to || !rule.byKeys) {
			return changed(op.value);
		}
		const inner = rule.move(key, from, op.to, op.value);
		return {
			needs: inner.needs,
			decide: (h, needed, attempt) => {
				const d = inner.decide(h, needed, attempt);
				const answer = d.answer === "moved" ? "ok" : d.answer;
				return { ...d, answer };
			},
		};
	};

	/**
	 * Changes the records `targets` names, and those `watch` names from what they hold, as one: the
	 * op `decide` gives each (or none), each held and written by its rule. Answers `written`, with
	 * each record's before and after, or `refused` at the first record whose op its rule refuses,
	 * nothing written. A move from a subject whose tombstone alone stands is Unavailable, nothing
	 * written: that record awaits its eraser. `decide` is pure: a race runs it again.
	 */
	const changeSubjectRecords = async (p: {
		readonly targets: readonly JointKey<P>[];
		readonly watch?: (read: readonly JointRead[]) => readonly JointKey<P>[];
		readonly decide: (
			read: readonly JointRead[],
			watched: readonly JointRead[],
			attempt: Attempt,
		) => {
			readonly targets?: readonly (JointOp | undefined)[];
			readonly watched?: readonly (JointOp | undefined)[];
		};
	}): Promise<JointAnswer> => {
		// The index records the ops need: grown until a decide's ops find all they need read.
		let needed: Target[] = [];
		for (;;) {
			let watchedNames: readonly JointKey<P>[] = [];
			let outcome:
				| { readonly kind: "again"; readonly more: readonly Target[] }
				| {
						readonly kind: "refused";
						readonly at: JointAt;
						readonly why: "exists" | "erased" | "missing";
				  }
				| { readonly kind: "unavailable" }
				| { readonly kind: "written" }
				| undefined;
			const reading = needed;
			const result = await changeRecords({
				targets: p.targets.map(targetOf),
				watch: (raw) => {
					const read = raw.map((held, at) => opened((p.targets[at] as JointKey<P>).place, held));
					watchedNames = p.watch?.(read) ?? [];
					return [...watchedNames.map(targetOf), ...reading];
				},
				decide: (raw, rawWatched, attempt) => {
					const names = [...p.targets, ...watchedNames];
					const helds = [...raw, ...rawWatched.slice(0, watchedNames.length)];
					const indexHeld = rawWatched.slice(watchedNames.length);
					const read = names.map((name, at) => opened(name.place, helds[at]));
					const ops = p.decide(
						read.slice(0, p.targets.length),
						read.slice(p.targets.length),
						attempt,
					);
					const allOps = [
						...p.targets.map((_, at) => ops.targets?.[at]),
						...watchedNames.map((_, at) => ops.watched?.[at]),
					];
					// What each index record holds as the ops so far leave it, so two ops on one bucket compose.
					const index = new Map(reading.map((t, at) => [idOf(t), indexHeld[at]]));
					// The last write an op gave each index record, with its own lifetime.
					const indexWrites = new Map<string, Next<Json>>();
					const missing = new Map<string, Target>();
					const records: Next<Json>[] = [];
					const seen = new Set<string>();
					for (const [at, op] of allOps.entries()) {
						if (op === undefined) continue;
						const name = names[at] as JointKey<P>;
						const id = idOf(targetOf(name));
						if (seen.has(id))
							throw new TypeError("subject-records: a record takes one op in a joint change");
						seen.add(id);
						const rule = ruleOf(name.place, name.key, helds[at], op);
						for (const t of rule.needs(helds[at])) if (!index.has(idOf(t))) missing.set(idOf(t), t);
						if (missing.size > 0) continue;
						const needs = rule.needs(helds[at]);
						const decided = rule.decide(
							helds[at],
							needs.map((t) => index.get(idOf(t))),
							attempt,
						);
						if (decided.answer === "from-erased") {
							outcome = { kind: "unavailable" };
							return {};
						}
						if (decided.answer !== "ok") {
							const where: JointAt =
								at < p.targets.length
									? { in: "targets", index: at }
									: { in: "watched", index: at - p.targets.length };
							outcome = { kind: "refused", at: where, why: decided.answer };
							return {};
						}
						records[at] = decided.record;
						for (const [n, next] of (decided.needed ?? []).entries()) {
							const t = needs[n] as Target;
							if (next === undefined) continue;
							index.set(idOf(t), "remove" in next ? undefined : (next.value as Json));
							indexWrites.set(idOf(t), next);
						}
					}
					if (missing.size > 0) {
						outcome = { kind: "again", more: [...missing.values()] };
						return {};
					}
					outcome = { kind: "written" };
					const indexNext = reading.map((t): Next<Json> => indexWrites.get(idOf(t)));
					return {
						targets: p.targets.map((_, at) => records[at]),
						watched: [...watchedNames.map((_, at) => records[p.targets.length + at]), ...indexNext],
					};
				},
			});
			const done = outcome as typeof outcome;
			if (done?.kind === "again") {
				needed = [...needed, ...done.more];
				continue;
			}
			if (done?.kind === "unavailable") throw new Unavailable("subject-records");
			if (done?.kind === "refused") return { kind: "refused", at: done.at, why: done.why };
			const shown = (name: JointKey<P>, changed: ChangedRecord | undefined): JointChanged => ({
				before: opened(name.place, changed?.before),
				after: opened(name.place, changed?.after),
			});
			return {
				kind: "written",
				targets: p.targets.map((name, at) => shown(name, result.targets[at])),
				watched: watchedNames.map((name, at) => shown(name, result.watched[at])),
			};
		}
	};
	return { changeSubjectRecords };
}
