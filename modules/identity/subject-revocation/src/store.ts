import { contract } from "@mod/kernel";

declare const storedBoundary: unique symbol;
/** A subject's boundary as the store keeps it: only subject-revocation opens it. */
export type StoredBoundary = { readonly [storedBoundary]: true };

/** A boundary write's own attempt, as the store hands it: the store-clock time past which that write is refused. */
export interface BoundaryWrite {
	readonly deadline: number;
}

/** Boundaries by subject, each changed only from what it holds, kept without end. Every call throws Unavailable when the place cannot tell. */
export interface BoundaryStore {
	/** Keeps a subject's first boundary, unless the subject holds one; one made from a write is made from each attempt's. */
	save(
		subject: string,
		record: StoredBoundary | ((write?: BoundaryWrite) => StoredBoundary),
		lifetimeMs: "endless",
	): Promise<"created" | "exists">;
	read(subject: string): Promise<StoredBoundary | undefined>;
	/**
	 * Writes the boundary from what it holds; `change` runs again on a race, so it is pure, handed
	 * each attempt's write. Nothing when gone.
	 */
	update(
		subject: string,
		change: (record: StoredBoundary, write?: BoundaryWrite) => StoredBoundary,
	): Promise<{ readonly before: StoredBoundary; readonly after: StoredBoundary } | undefined>;
}

export const boundaryStore = contract<BoundaryStore>("subject-revocation.boundary-store");

/** Losing a boundary would let revoked authentications back. */
export const boundaryStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;
