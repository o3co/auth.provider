import { contract } from "@mod/kernel";

declare const storedBoundary: unique symbol;
/** A subject's boundary as the store keeps it: only subject-revocation opens it. */
export type StoredBoundary = { readonly [storedBoundary]: true };

declare const storedReceipt: unique symbol;
/** A fence's receipt as the store keeps it: only subject-revocation opens it. */
export type StoredReceipt = { readonly [storedReceipt]: true };

/** A receipt as a fence writes it: the receipt, and how long it is kept. */
export interface ReceiptWrite {
	readonly value: StoredReceipt;
	readonly lifetimeMs: number;
}

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
	 * Writes under `receiptId` the receipt `allowed` answers from the subject's boundary (none
	 * where it holds none), for the lifetime it answers, in one write held by the boundary as read:
	 * `allowed` runs again when the boundary changes first, so it is pure. Writes nothing where it
	 * answers none. Answers the receipt held under `receiptId` before the write and after it. Where
	 * it is absent, the composition is unguarded: the boot gate refuses it where erasure reads
	 * enabled; where `erasureEnabled` is absent too, that cannot be read, the stated exclusion.
	 */
	fence?(
		subject: string,
		receiptId: string,
		allowed: (record: StoredBoundary | undefined) => ReceiptWrite | undefined,
	): Promise<{
		readonly before: StoredReceipt | undefined;
		readonly after: StoredReceipt | undefined;
	}>;
	/**
	 * Whether erasure is enabled for the store's data: read as the store keeps it, and once enabled
	 * in any epoch, enabled. Where it is absent, erasure is taken as off at start and for readiness,
	 * with a warning at every start, and a store with `fence` fences every bundle of a guarded
	 * composition; 0.22 refuses it.
	 */
	erasureEnabled?(): Promise<boolean>;
}

export const boundaryStore = contract<BoundaryStore>("subject-revocation.boundary-store");

/**
 * A boundary store's `fence` where its store `can` write the receipt and the boundary as one, made
 * then and only then, and none where it cannot: a wiring spreads the answer with no branch of its own.
 */
export function fenceWhere(
	can: boolean,
	fence: () => NonNullable<BoundaryStore["fence"]>,
): Pick<BoundaryStore, "fence"> {
	return can ? { fence: fence() } : {};
}

/** Losing a boundary would let revoked authentications back. */
export const boundaryStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;
