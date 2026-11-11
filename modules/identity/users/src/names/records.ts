import { Unavailable } from "@mod/kernel";
import {
	type Changed,
	type LinkStore,
	type NameStore,
	type RecordStore,
	type StoredLink,
	type StoredName,
	written,
} from "../store.ts";

/** Where a name's record is kept, as names reads and writes it. */
export interface NameRecords {
	/** The stores that keep them, as a refusal names them. */
	readonly stores: string;
	read(key: string): Promise<StoredName | undefined>;
	/** Changes the record, or keeps `first` where none is; answers what is kept after. */
	written(
		key: string,
		first: StoredName,
		change: (record: StoredName) => Changed<StoredName> | undefined,
	): Promise<{ readonly after: StoredName }>;
	/** Brings the copy in step with the record kept, where there is a copy. */
	copied(key: string): Promise<void>;
}

/** Reads of a record kept between attempts, before a write that keeps meeting another's is unavailable. */
const attempts = 8;

/**
 * Names' records in the link space alone, as before `names`: no copy. `saveName` is users' view of
 * the link store's `save` called without a subject, as before 0.20, for a name holds none: a type
 * over the same method, never one an implementation writes.
 */
function inLinks(links: LinkStore): NameRecords {
	// Called on the store, as before, so an implementation keeps its own `this`.
	const viewed = links as unknown as RecordStore<StoredName>;
	const saveName: RecordStore<StoredName>["save"] = (key, record, lifetimeMs) =>
		viewed.save(key, record, lifetimeMs);
	const asNames: RecordStore<StoredName> = {
		save: saveName,
		read: (key) => viewed.read(key),
		update: (key, change) => viewed.update(key, change),
	};
	return {
		stores: "the link store",
		read: asNames.read,
		written: (key, first, change) => written(asNames, key, first, change),
		copied: async () => {},
	};
}

/**
 * Names' records with a name store: the link space is the record until the one migration takes
 * names out of it, the name store a copy brought in step at each write and each boot; once the
 * link space keeps no such record (`unowned` answers `closed`), the name store is the record.
 */
function split(links: LinkStore, unowned: NonNullable<LinkStore["unowned"]>, names: NameStore) {
	const fromLinks = async (key: string) =>
		(await links.read(key)) as unknown as StoredName | undefined;
	const asLinks = (change: (record: StoredName) => Changed<StoredName> | undefined) =>
		change as unknown as (record: StoredLink) => Changed<StoredLink> | undefined;
	/** The copy made what the link space keeps: saved where absent, else rewritten to it. */
	const copyOf = async (key: string, kept: StoredName) => {
		const same = JSON.stringify(kept);
		const align = (record: StoredName) =>
			JSON.stringify(record) === same ? undefined : { value: kept };
		await written(names, key, kept, align);
	};
	const records: NameRecords = {
		stores: "the link store or the name store",
		read: async (key) => (await fromLinks(key)) ?? (await names.read(key)),
		written: async (key, first, change) => {
			for (let attempt = 0; attempt < attempts; attempt += 1) {
				const inLinksNow = await links.update(key, asLinks(change));
				if (inLinksNow) {
					const after = inLinksNow.after as unknown as StoredName;
					await copyOf(key, after);
					return { after };
				}
				// Kept in the name store alone: read as kept, and no record made again in the link space.
				const inNames = await names.update(key, change);
				if (inNames) return { after: inNames.after };
				const saved = await unowned(key, first, "endless");
				if (saved === "closed") return written(names, key, first, change);
				if (saved === "created") {
					await copyOf(key, first);
					return { after: first };
				}
				// Another instance saved it first: changed from what it holds, at the next attempt.
			}
			throw new Unavailable("users");
		},
		copied: async (key) => {
			const kept = await fromLinks(key);
			if (kept !== undefined) await copyOf(key, kept);
		},
	};
	return records;
}

/** Names' records over the link store: its `names` and `unowned` where offered, else the link space alone. */
export function nameRecordsOver(links: LinkStore): NameRecords {
	const { names } = links;
	if (names === undefined && links.unowned === undefined) return inLinks(links);
	if (names === undefined || links.unowned === undefined) {
		throw new TypeError("users: the link store offers names and unowned together, or neither");
	}
	// Called on the store, so an implementation keeps its own `this`.
	const unowned: NonNullable<LinkStore["unowned"]> = async (key, record, lifetimeMs) => {
		if (links.unowned === undefined) throw new TypeError("users: the link store's unowned went");
		return links.unowned(key, record, lifetimeMs);
	};
	return split(links, unowned, names);
}
