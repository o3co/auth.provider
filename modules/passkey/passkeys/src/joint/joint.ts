import { holderOf, type KeptRecords, stored } from "../records/records.ts";
import type { ChangedPasskey, PasskeyStore, StoredPasskey } from "../store.ts";
import { registeringWith } from "./registering.ts";
import { removingWith } from "./removing.ts";

/** The holder a write that emptied its list left: its handle, which names the holder's incarnation, and its fence. */
export interface Emptied {
	readonly handle: string;
	readonly fence: number;
}

/** What the writes share: the store's one change across both spaces, and what a change did to a list. */
export function listsOf(store: PasskeyStore) {
	/** The holder a change left, where it emptied the list. */
	const emptiedBy = (changed: ChangedPasskey | undefined): Emptied | undefined => {
		const [before, after] = [changed?.before, changed?.after].map((r) => r && holderOf(r));
		if (!after || after.credentials.length > 0 || after.fence === before?.fence) return undefined;
		return { handle: after.handle, fence: after.fence };
	};
	/** What a change of the subject's holder did to an id: `removed` where it took it off, `empty` where none is left, `emptied` the holder left where it emptied the list. */
	const delistedBy = (changed: ChangedPasskey | undefined, id: string) => {
		const [before, after] = [changed?.before, changed?.after].map((r) =>
			r === undefined ? [] : holderOf(r).credentials,
		);
		const removed = !!before?.includes(id) && !after?.includes(id);
		const emptied = removed ? emptiedBy(changed) : undefined;
		return { removed, empty: after?.length === 0, ...(emptied && { emptied }) };
	};
	/** The subject's holder listing `list`, its fence moved on where `list` empties it. */
	const listing = (ours: StoredPasskey, list: readonly string[]) => {
		const held = holderOf(ours);
		const fence = list.length === 0 && held.credentials.length > 0 ? held.fence + 1 : held.fence;
		return stored({ ...ours, credentials: list, fence });
	};
	return { together: store.updateTogether.bind(store), emptiedBy, delistedBy, listing };
}

export type Lists = ReturnType<typeof listsOf>;

/**
 * The writes that change a list: a registration's, an end, a removal and a clear, each the
 * credential's record and the subject's list, or the list and every record it names, in one change,
 * so a list names an id exactly while the record names the subject, pending or a passkey; and what a
 * write that emptied a list leaves (`afterRemoval`).
 */
export function jointOver(store: PasskeyStore, holder: KeptRecords["holder"], now: () => number) {
	const lists = listsOf(store);
	return {
		...registeringWith(lists, holder, now),
		...removingWith(store, lists, holder),
	};
}

export type JointWrites = ReturnType<typeof jointOver>;
