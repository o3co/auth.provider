import { Unavailable } from "@mod/kernel";
import type { Changed, SubjectRecordStore } from "./store.ts";

/** Attempts at a record a create met and a read then found gone, before it is unavailable. */
const attempts = 8;

/**
 * Changes a subject's record, or saves `first` for the subject where there is none; one saved
 * meanwhile is changed from what it holds, and one removed meanwhile is saved again, at most
 * `attempts` times: a record can now go, so `exists` then absent is no proof of anything.
 */
export async function keptFor<T>(
	store: SubjectRecordStore<T>,
	key: string,
	first: T,
	change: (record: T) => Changed<T> | undefined,
	subject: string,
): Promise<{ readonly before: T | undefined; readonly after: T }> {
	for (let attempt = 0; attempt < attempts; attempt += 1) {
		const changed = await store.update(key, change);
		if (changed) return changed;
		if ((await store.save(key, first, "endless", subject)) === "created") {
			return { before: undefined, after: first };
		}
	}
	throw new Unavailable("users");
}
