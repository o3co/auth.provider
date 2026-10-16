import { contract } from "@mod/kernel";

declare const storedFactors: unique symbol;
/** A subject's factors, or a claim on a unique value, as the store keeps them: only mfa opens them. */
export type StoredFactors = { readonly [storedFactors]: true };

export interface ChangedFactors {
	readonly value: StoredFactors;
}

/** Factor lists and claims by keys mfa makes, each changed only from what it holds, kept without end. Every call throws Unavailable when the place cannot tell. */
export interface FactorStore {
	/** Keeps a subject's first list, unless the key holds one. */
	save(key: string, record: StoredFactors): Promise<"created" | "exists">;
	read(key: string): Promise<StoredFactors | undefined>;
	/** Changes the list from what it holds; `change` runs again on a race, so it is pure; none leaves it. Nothing when gone. */
	update(
		key: string,
		change: (record: StoredFactors) => ChangedFactors | undefined,
	): Promise<{ readonly before: StoredFactors; readonly after: StoredFactors } | undefined>;
	/** A page of the keys holding a list or a claim, and the cursor on; none when done. A walk is no one instant. */
	scan?(cursor?: string): Promise<{ readonly keys: readonly string[]; readonly cursor?: string }>;
}

export const factorStore = contract<FactorStore>("mfa.factor-store");

/** Another request writes an added factor, and a login is stopped by reading it; a lost factor or used proof would come back. */
export const factorStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	confirmedReads: true,
} as const;
