import type { Json } from "@mod/store";
import { plantValue } from "@mod/store/testing";
import { changeRecords, type Target } from "../together/together.ts";
import { expiryOf } from "../writing/writing.ts";

/**
 * Writes `value` as the record `target` names, in records' key layout, as an earlier version left it
 * (a record as 0.19 wrote it, say): over store's `plantValue`, ending `lifetimeMs` from the write as
 * records' changes end one (`expiryOf`), or endless without one. A target is any records takes: by
 * key (a keyed set's too), under a secret, or by a secret's kept name. For tests alone; it throws
 * where the store does not commit it.
 */
export async function plantRecord(target: Target, value: Json, lifetimeMs?: number): Promise<void> {
	const expiry = expiryOf(lifetimeMs ?? "endless");
	const key = changeRecords.keyOf(target);
	const answer = await plantValue(target.place.store, key, value, expiry);
	if (answer.kind !== "committed")
		throw new Error(`plantRecord: the store answered ${answer.kind}`);
}
