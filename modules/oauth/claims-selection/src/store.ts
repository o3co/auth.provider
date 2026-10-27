import { contract } from "@mod/kernel";

declare const stored: unique symbol;
/** A selection's record as the store keeps it: the store never reads it, and only claims-selection opens it. */
export type StoredSelection = { readonly [stored]: true };

/** Where selections are kept, by name. Every call throws Unavailable when the place cannot tell. */
export interface SelectionRecords {
	/** Keeps a record for its lifetime, unless the name holds one already. */
	save(name: string, record: StoredSelection, lifetimeMs: number): Promise<"created" | "exists">;
	read(name: string): Promise<StoredSelection | undefined>;
}

export const selectionRecords = contract<SelectionRecords>("claims-selection.records");

/**
 * A lost record would let a claim its constraint holds back go out unconstrained, so none is lost
 * to eviction, a crash or a failover.
 */
export const selectionRecordsNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;

/**
 * The families whose kept selection holds constraints, listed until done, so that going back to a
 * release before 0.19 finds every one. Every call throws Unavailable when the place cannot tell.
 */
export interface ConstrainedFamilyList {
	/** Lists a family, once however often; a full place refuses it as unavailable. */
	add(familyId: string): Promise<void>;
	done(familyId: string): Promise<void>;
	/** Hands each listed family to `handle`; a part that cannot be read, or a family whose handling fails, stays and is counted. */
	each(handle: (familyId: string) => Promise<void>): Promise<{ readonly failed: number }>;
}

/** Its needs are the records': a family dropped from it would be missed. */
export const constrainedFamilyList = contract<ConstrainedFamilyList>(
	"claims-selection.constrained-families",
);
