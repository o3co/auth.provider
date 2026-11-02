import { createHash } from "node:crypto";
import type {
	PasskeyKeys,
	PasskeyRecords,
	PasskeyStore,
	PasskeysNext,
	PasskeysRead,
	StoredPasskey,
} from "@mod/passkeys";

type Space = keyof PasskeyKeys;
const hashOf = (value: string) => createHash("sha256").update(value).digest("base64url");

/** The keys passkeys keeps a subject's holder and a credential's record under. */
export const keyOf = {
	holder: (subject: string) => `s-${hashOf(subject)}`,
	record: (id: string) => `c-${hashOf(id)}`,
};

/**
 * A passkey store over `inner` that can lose what it keeps, or go back to an old copy, as a store
 * that broke its promises would. What it shows for a key (none, where lost) stands until a write
 * of that key replaces it; everything else is `inner`'s.
 */
export function lossy(inner: PasskeyStore) {
	const shown: Record<Space, Map<string, StoredPasskey | undefined>> = {
		credentials: new Map(),
		subjects: new Map(),
	};
	const view = (space: Space, key: string | undefined, raw: StoredPasskey | undefined) =>
		key !== undefined && shown[space].has(key) ? shown[space].get(key) : raw;
	/** Writes `record` under `key` in `inner`, whatever it holds, and shows `inner` again. */
	const put = async (space: Space, key: string, record: StoredPasskey) => {
		shown[space].delete(key);
		if ((await inner[space].update(key, () => ({ value: record }))) === undefined) {
			await inner[space].save(key, record, "endless");
		}
	};
	const records = (space: Space): PasskeyRecords => ({
		read: async (key) => view(space, key, await inner[space].read(key)),
		save: async (key, record, lifetimeMs) => {
			if (!shown[space].has(key)) return inner[space].save(key, record, lifetimeMs);
			if (shown[space].get(key) !== undefined) return "exists";
			await put(space, key, record);
			return "created";
		},
		update: async (key, change) => {
			if (!shown[space].has(key)) return inner[space].update(key, change);
			const before = shown[space].get(key);
			if (before === undefined) return undefined;
			const next = change(before);
			if (!next) return { before, after: before };
			await put(space, key, next.value);
			return { before, after: next.value };
		},
	});
	const store: PasskeyStore = {
		credentials: records("credentials"),
		subjects: records("subjects"),
		updateTogether: async (keys, p) => {
			let watched: Partial<PasskeyKeys> = {};
			let seen: PasskeysRead = { credentials: [], subjects: [] };
			let wrote: PasskeysNext = {};
			const all = (space: Space) => [...keys[space], ...(watched[space] ?? [])];
			const viewed = (read: PasskeysRead): PasskeysRead => ({
				credentials: read.credentials.map((r, i) => view("credentials", all("credentials")[i], r)),
				subjects: read.subjects.map((r, i) => view("subjects", all("subjects")[i], r)),
			});
			const changed = await inner.updateTogether(keys, {
				watch: (read) => {
					watched = {};
					watched = p.watch(viewed(read));
					return watched;
				},
				change: (read) => {
					seen = viewed(read);
					wrote = p.change(seen);
					return wrote;
				},
			});
			const remapped = (space: Space) =>
				changed[space].map((c, i) => {
					const before = seen[space][i];
					if (wrote[space]?.[i] === undefined) return { before, after: before };
					const key = all(space)[i];
					if (key !== undefined) shown[space].delete(key);
					return { before, after: c.after };
				});
			return { credentials: remapped("credentials"), subjects: remapped("subjects") };
		},
	};
	return {
		store,
		/** The store forgets the subject's holder, or the id's record. */
		lose: {
			holder: (subject: string) => void shown.subjects.set(keyOf.holder(subject), undefined),
			record: (id: string) => void shown.credentials.set(keyOf.record(id), undefined),
		},
		/** The subject's holder as kept now. */
		holderCopy: (subject: string) => store.subjects.read(keyOf.holder(subject)),
		/** The store goes back to `record` for the subject's holder. */
		backTo: (subject: string, record: object) =>
			void shown.subjects.set(keyOf.holder(subject), record as StoredPasskey),
	};
}
