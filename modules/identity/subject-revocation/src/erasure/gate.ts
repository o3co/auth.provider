import { isUnavailable, Unavailable } from "@mod/kernel";
import { markIn, opened } from "../boundaries/written.ts";
import type { ErasureFence } from "../contract.ts";
import type { BoundaryStore, StoredBoundary, StoredReceipt } from "../store.ts";

/**
 * How long a fence's receipt is kept: a minute, fixed. Nothing reads a receipt; it outlives the
 * fence's own write and its resends (records' 10-second deadline and a second).
 */
export const receiptLifetimeMs = 60_000;

/**
 * Whether erasure is enabled, as this module reads it: `on` or `off` once the store's mark is read,
 * held for the process (enabling it restarts every node); `unread` while the store cannot answer,
 * read again the next time; `cannot-tell` where the store has no reading at all.
 */
export type Enablement = "on" | "off" | "unread" | "cannot-tell";

/** The one reading of whether erasure is enabled: `cannotTell` is known without the store. */
export function erasureMark(boundaries: BoundaryStore): {
	readonly cannotTell: boolean;
	readonly read: () => Promise<Enablement>;
} {
	const reading = boundaries.erasureEnabled?.bind(boundaries);
	let held: "on" | "off" | undefined;
	return {
		cannotTell: reading === undefined,
		read: async () => {
			if (reading === undefined) return "cannot-tell";
			if (held !== undefined) return held;
			try {
				held = (await reading()) ? "on" : "off";
				return held;
			} catch (error) {
				if (isUnavailable(error)) return "unread";
				throw error;
			}
		},
	};
}

const receipt = (id: string) => ({
	value: { id } as unknown as StoredReceipt,
	lifetimeMs: receiptLifetimeMs,
});

/**
 * The fence over the store: no write where erasure reads off; else the receipt, where the
 * subject's boundary holds no mark. Unread fences, the closed side, as does a store that fences
 * but cannot tell; one that can neither tell nor fence passes, the stated exclusion.
 */
export function fenceOver(
	boundaries: BoundaryStore,
	enabled: () => Promise<Enablement>,
): ErasureFence {
	return {
		fence: async (subject, receiptId) => {
			const state = await enabled();
			if (state === "off") return "passed";
			if (!boundaries.fence) {
				if (state === "cannot-tell") return "passed";
				throw new Unavailable("subject-revocation");
			}
			const allowed = (record: StoredBoundary | undefined) => {
				if (record === undefined) return receipt(receiptId);
				// A mark of a time is erased, whatever else the record holds, as marking answers it.
				if (typeof markIn(record) === "number") return undefined;
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
