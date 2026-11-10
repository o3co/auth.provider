import { contract } from "@mod/kernel";

declare const storedBoundary: unique symbol;
/** A subject's boundary as the store keeps it: only subject-revocation opens it. */
export type StoredBoundary = { readonly [storedBoundary]: true };

declare const storedReceipt: unique symbol;
/** A fence's receipt as the store keeps it: only subject-revocation opens it. */
export type StoredReceipt = { readonly [storedReceipt]: true };

/** A boundary write's own attempt, as the store hands it: the store-clock time past which that write is refused. */
export interface BoundaryWrite {
	readonly deadline: number;
}

/** Boundaries by subject, each changed only from what it holds, kept without end. Every call throws Unavailable when the place cannot tell. */
export interface BoundaryStore {
	/** Keeps a subject's first boundary, unless the subject holds one, made from each attempt's write. */
	save(
		subject: string,
		record: (write: BoundaryWrite) => StoredBoundary,
		lifetimeMs: "endless",
	): Promise<"created" | "exists">;
	read(subject: string): Promise<StoredBoundary | undefined>;
	/**
	 * Writes the boundary from what it holds; `change` runs again on a race, so it is pure, handed
	 * each attempt's write. Nothing when gone.
	 */
	update(
		subject: string,
		change: (record: StoredBoundary, write: BoundaryWrite) => StoredBoundary,
	): Promise<{ readonly before: StoredBoundary; readonly after: StoredBoundary } | undefined>;
	/**
	 * Keeps the receipt `allowed` makes from the subject's boundary (none where it holds none),
	 * under `receiptId` for `lifetimeMs`, in one write held by the boundary as read: `allowed` runs
	 * again when the boundary changes first, so it is pure. Writes nothing where it answers none.
	 * Where it is absent, erasure cannot be enabled (`subject-revocation`'s boot gate).
	 */
	fence?(
		subject: string,
		receiptId: string,
		allowed: (record: StoredBoundary | undefined) => StoredReceipt | undefined,
		lifetimeMs: number,
	): Promise<{
		readonly before: StoredReceipt | undefined;
		readonly after: StoredReceipt | undefined;
	}>;
	/**
	 * Whether erasure is enabled for the store's data: read as the store keeps it, and once enabled
	 * in any epoch, enabled. Where it is absent, erasure is taken as off, with a warning at every
	 * start; 0.22 refuses such a store.
	 */
	erasureEnabled?(): Promise<boolean>;
}

export const boundaryStore = contract<BoundaryStore>("subject-revocation.boundary-store");

/** Losing a boundary would let revoked authentications back. */
export const boundaryStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;
