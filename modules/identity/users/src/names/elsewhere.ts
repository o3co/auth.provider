import type { Elsewhere, SubjectOf } from "@mod/erasure-extensions";
import { Unavailable } from "@mod/kernel";
import { type NameStore, type StoredName, written } from "../store.ts";

/** A key names keeps an IdP name's record under, in the link space: `{"idp":<name>}`, where a link's is a list. */
export const isNameKey = (key: string): boolean => {
	try {
		const read: unknown = JSON.parse(key);
		return (
			read !== null &&
			typeof read === "object" &&
			!Array.isArray(read) &&
			Object.keys(read).length === 1 &&
			typeof (read as { idp?: unknown }).idp === "string"
		);
	} catch {
		return false;
	}
};

/** A name's record exactly: `{ issuer }`, a string, and nothing else, which could be a subject's data. */
export const isNameRecord = (value: unknown): boolean =>
	value !== null &&
	typeof value === "object" &&
	!Array.isArray(value) &&
	Object.keys(value).length === 1 &&
	typeof (value as { issuer?: unknown }).issuer === "string";

export const nameSubjectOf = (value: unknown): SubjectOf =>
	isNameRecord(value)
		? { kind: "orphan" }
		: { kind: "unreadable", reason: "a name's record of another shape" };

/**
 * names' `Elsewhere`: a name's record kept in the name store as the link space, the authority, holds
 * it, then read back confirmed before it may go; nothing for any other key.
 */
export function namesKept(names: NameStore): Elsewhere {
	return async (key, value) => {
		if (!isNameKey(key)) return;
		const kept = value as StoredName;
		const same = JSON.stringify(kept);
		await written(names, key, kept, (record) =>
			JSON.stringify(record) === same ? undefined : { value: kept },
		);
		// The name store's reads are confirmed (its needs): what is read back holds through a failover.
		const now = await names.read(key);
		if (JSON.stringify(now) !== same) throw new Unavailable("users");
	};
}
