import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { contract } from "@mod/kernel";

declare const storedFactors: unique symbol;
/** A subject's factors, or a claim on a unique value, as the store keeps them: only mfa opens them. */
export type StoredFactors = { readonly [storedFactors]: true };

export interface ChangedFactors {
	readonly value: StoredFactors;
}

/** A record of the factor store, as a change as one names it: its space, and its key. */
export interface FactorKey {
	readonly place: "factors";
	readonly key: string;
}

/** A record as a change as one reads it: its value, and the subject the Store keeps it for; none, kept raw. */
export type FactorRead = { readonly value: StoredFactors; readonly subject?: string } | undefined;

/** What a change as one does to one record; its words are subject-records' joint change's. */
export type FactorOp =
	| {
			readonly kind: "create";
			readonly value: StoredFactors;
			readonly lifetimeMs: "endless";
			readonly subject: string;
	  }
	| { readonly kind: "change"; readonly value: StoredFactors }
	| { readonly kind: "remove" }
	| { readonly kind: "move"; readonly value: StoredFactors; readonly to: string };

/** A record of a change as one: what it held, and holds after. */
export interface FactorChanged {
	readonly before: FactorRead;
	readonly after: FactorRead;
}

/** A change as one, whole: written, or refused at one record (`nth` in its list), nothing written. */
export type FactorsAnswer =
	| {
			readonly kind: "written";
			readonly targets: readonly FactorChanged[];
			readonly watched: readonly FactorChanged[];
	  }
	| {
			readonly kind: "refused";
			readonly at: { readonly in: "targets" | "watched"; readonly nth: number };
			readonly why: "exists" | "erased" | "missing";
	  };

/** Factor lists and claims by keys mfa makes, each changed only from what it holds, kept without end. Every call throws Unavailable when the place cannot tell. */
export interface FactorStore {
	/**
	 * Keeps a subject's first list, unless the key holds one (`exists`) or, where the Store fences
	 * saves past a subject's erasure, the subject is erased there (`erased`). The subject comes last.
	 */
	save(
		key: string,
		record: StoredFactors,
		lifetimeMs: "endless",
		subject: string,
	): Promise<"created" | "exists" | "erased">;
	read(key: string): Promise<StoredFactors | undefined>;
	/**
	 * Changes the list from what it holds; `change` runs again on a race, so it is pure; none leaves
	 * it. Nothing when gone, or, where the Store fences saves past a subject's erasure, when its
	 * subject is erased.
	 */
	update(
		key: string,
		change: (record: StoredFactors) => ChangedFactors | undefined,
	): Promise<{ readonly before: StoredFactors; readonly after: StoredFactors } | undefined>;
	/**
	 * Changes records of this store as one: those `targets` names, and those `watch` names from what
	 * they hold, each by the op `decide` gives it, written as one, or refused at one record, nothing
	 * written; `decide` runs again on a race, so it is pure. Its words are subject-records' joint
	 * change's: `create`, `change`, `remove` and `move` (to a subject, from the one it is read under);
	 * `refused` with `exists`, `erased` or `missing`. Where the Store fences saves past a subject's
	 * erasure, a move from a subject whose tombstone alone stands is Unavailable.
	 */
	updateAsOne(p: {
		readonly targets: readonly FactorKey[];
		readonly watch?: (read: readonly FactorRead[]) => readonly FactorKey[];
		readonly decide: (
			read: readonly FactorRead[],
			watched: readonly FactorRead[],
		) => {
			readonly targets?: readonly (FactorOp | undefined)[];
			readonly watched?: readonly (FactorOp | undefined)[];
		};
	}): Promise<FactorsAnswer>;
	/**
	 * Erases a subject's lists and claims here, where the Store can: optional in 0.20, required in
	 * 0.22. `erase` and `migrate` come together or none; a part refuses the boot.
	 */
	erase?(subject: string, signal: AbortSignal): Promise<SpaceReport>;
	/** Once, under the maintenance key, each list and claim read by mfa's reading; optional as `erase` is. */
	migrate?(walk: Walk, reading: SubjectReading, signal: AbortSignal): Promise<MigrationReport>;
	/** A page of the keys holding a list or a claim, and the cursor on; none when done. A walk is no one instant. */
	scan(cursor?: string): Promise<{ readonly keys: readonly string[]; readonly cursor?: string }>;
}

export const factorStore = contract<FactorStore>("mfa.factor-store");

/** Another request writes an added factor, and a login is stopped by reading it; a lost factor or used proof would come back. */
export const factorStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	confirmedReads: true,
} as const;
