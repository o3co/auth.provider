import { isUnavailable, Unavailable } from "@mod/kernel";
import { opened } from "../boundaries/written.ts";
import type { ErasureFence } from "../contract.ts";
import type { BoundaryStore, StoredBoundary, StoredReceipt } from "../store.ts";

/**
 * How long a fence's receipt is kept: a minute, fixed. Nothing reads a receipt; it outlives the
 * fence's own write and its resends (records' 10-second deadline and a second).
 */
export const receiptLifetimeMs = 60_000;

/**
 * Whether erasure is enabled, as read: `undefined` until the store's mark is read once, then what
 * it read, which holds for the process (enabling it restarts every node). A store that cannot tell
 * at all answers off.
 */
export function erasureMark(boundaries: BoundaryStore): () => Promise<boolean | undefined> {
	let known: boolean | undefined;
	return async () => {
		if (known !== undefined) return known;
		if (!boundaries.erasureEnabled) return false;
		try {
			known = await boundaries.erasureEnabled();
			return known;
		} catch (error) {
			if (isUnavailable(error)) return undefined;
			throw error;
		}
	};
}

const receipt = (id: string) => ({
	value: { id } as unknown as StoredReceipt,
	lifetimeMs: receiptLifetimeMs,
});

/**
 * The fence over the store: no write where erasure is read as off; else the receipt, where the
 * subject's boundary holds no mark. A mark not yet read fences, the closed side.
 */
export function fenceOver(
	boundaries: BoundaryStore,
	enabled: () => Promise<boolean | undefined>,
): ErasureFence {
	return {
		fence: async (subject, receiptId) => {
			if ((await enabled()) === false) return "passed";
			if (!boundaries.fence) throw new Unavailable("subject-revocation");
			const allowed = (record: StoredBoundary | undefined) => {
				if (record === undefined) return receipt(receiptId);
				const held = opened(record);
				if (held === undefined) throw new Unavailable("subject-revocation");
				return held.erasedAt === undefined ? receipt(receiptId) : undefined;
			};
			const { before, after } = await boundaries.fence(subject, receiptId, allowed);
			// A receipt kept from before is no answer of this fence, passed or not.
			if (before !== undefined) throw new Error("subject-revocation: a fence's receipt id is used");
			return after === undefined ? "erased" : "passed";
		},
	};
}
