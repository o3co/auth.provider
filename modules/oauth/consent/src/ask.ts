import type { Asked } from "./contract.ts";
import type { StoredAsk } from "./store.ts";

/** A pending consent as consent keeps it: past its deadline on the composition's clock it is gone, answered it is spent. */
export type Pending = Asked & {
	readonly subject: string;
	readonly deadline: number;
	readonly answer?: "accept" | "deny";
};

/** The challenge has a fixed length and no dot, so the pair reads back one way. */
export const askKey = (handle: string, challenge: string) => `${challenge}.${handle}`;

export function pendingOf(record: StoredAsk): Pending;
export function pendingOf(record: StoredAsk | undefined): Pending | undefined;
export function pendingOf(record: StoredAsk | undefined) {
	return record as unknown as Pending | undefined;
}
export const storedOf = (pending: Pending) => pending as unknown as StoredAsk;
