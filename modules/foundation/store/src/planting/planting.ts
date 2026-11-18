import type { Expiry, Json, Key, Store } from "../contract.ts";
import { subjectWriter } from "../writer/subject-writer.ts";

/**
 * Writes `value` at `key` as an earlier version, or another writer, left it (a record as 0.19 wrote
 * it, say): one batch with no conditions, carrying the subject writer, so a space of subjects' data
 * takes it as any other. For tests alone: shipped code changes subjects' data through
 * `subject-records`.
 */
export const plantValue = (store: Store, key: Key, value: Json, expiry: Expiry) =>
	store.batch([], [{ key, put: value, expiry }], { writer: subjectWriter });
