import type { MigrationReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { Unavailable } from "@mod/kernel";
import { changeRecords, type Target } from "@mod/records";
import { canonicalJson, type Json } from "@mod/store";
import { kept, opened } from "../envelope/envelope.ts";
import {
	checkedSubjectPlace,
	entriesIn,
	indexOver,
	listedWith,
	type SubjectPlace,
	UnreadableIndex,
	witnessed,
} from "../index/index.ts";

/** The one place a migration's report is made; nothing outside this package makes one. */
const report = (made: { kind: string; space: string } & Record<string, unknown>) =>
	made as unknown as MigrationReport;

/** Reads of one record before it is unavailable, where its value keeps changing between a read and its write. */
const rereads = 8;
/** Times a walk starts over, its server changing, before the space stops. */
const restarts = 8;

/** What one record came to. */
type Outcome =
	| { readonly kind: "indexed" | "removed" | "already" | "gone" }
	| { readonly kind: "stopped"; readonly reason: string };

/**
 * Puts the records of one space written before indexing into its index, once records are indexed
 * (account erasure §5.1): each raw record its owner's `subjectOf` reads as a subject's is kept in
 * an envelope with that subject, listed in its bucket (`online-indexed`) or written with its
 * witness (`online-keyed`), its value and its end as they were; each it proves an orphan is
 * removed; one it cannot read stops the space, removing nothing more. A record is already migrated
 * only where its envelope is listed or witnessed, never by its shape alone, so a rerun, a key a
 * walk meets twice, and two runs at once each index or remove a record once. Each write holds the
 * record as read. A `bounded` space has nothing to index. Keyed sets wait for their own migration.
 * Stops between records where `signal` aborts; running again finishes.
 */
export async function migrateRecords(
	place: SubjectPlace,
	walk: Walk,
	subjectOf: SubjectReading,
	options: { readonly signal?: AbortSignal } = {},
): Promise<MigrationReport> {
	const category = checkedSubjectPlace(
		place,
		["online-indexed", "online-keyed", "bounded"],
		"subject-records",
		(_, reason) => {
			throw new TypeError(`subject-records: ${place.space.name}: ${reason}`);
		},
	);
	const space = place.space.name;
	const stopped = (reason: string) => report({ kind: "stopped", space, reason });
	if (place.phase !== "indexed") return stopped("not-indexed");
	if (category === "bounded") return report({ kind: "migrated", space, indexed: 0, removed: 0 });
	const keyed = category === "online-keyed";
	const { bucketOf, witnessOf } = indexOver(place, place.space, place.index);
	const name = changeRecords.keyOf({ place, key: "" }).name;
	/** Where an envelope of `subject` at `key` is shown to be subject-records' own. */
	const markOf = (subject: string, key: string): Target =>
		keyed ? witnessOf(subject, "record") : bucketOf(subject, key);
	const marks = (mark: Json | undefined, key: string) =>
		keyed
			? mark !== undefined
			: entriesIn(mark, space).some((e) => e.key === key && e.name === "record");
	const isMigrated = (held: Json, mark: Json | undefined, key: string) => {
		const { subject } = opened(held, true);
		return subject !== undefined && marks(mark, key);
	};

	const migrated = async (key: string): Promise<Outcome> => {
		const target: Target = { place, key };
		for (let read = 0; read < rereads; read += 1) {
			const { entry } = await place.store.get(changeRecords.keyOf(target));
			if (!entry) return { kind: "gone" };
			const value = entry.value;
			const { subject: shaped } = opened(value, true);
			if (shaped !== undefined) {
				const { entry: mark } = await place.store.get(changeRecords.keyOf(markOf(shaped, key)));
				if (marks(mark?.value, key)) return { kind: "already" };
			}
			const whose = await subjectOf(key, value);
			if (whose.kind === "unreadable")
				return { kind: "stopped", reason: `unreadable: ${whose.reason}` };
			const subject = whose.kind === "subject" ? whose.subject : undefined;
			if (keyed && subject !== undefined && subject !== key) {
				return { kind: "stopped", reason: "a record keyed by another subject" };
			}
			let outcome: Outcome["kind"] = "gone";
			let changed = false;
			await changeRecords({
				targets: subject === undefined ? [target] : [target, markOf(subject, key)],
				decide: ([held, mark]) => {
					if (held === undefined) {
						outcome = "gone";
						return {};
					}
					if (canonicalJson(held) !== canonicalJson(value)) {
						changed = true;
						return {};
					}
					changed = false;
					if (subject === undefined) {
						outcome = "removed";
						return { targets: [{ remove: true }] };
					}
					if (isMigrated(held, mark, key)) {
						outcome = "already";
						return {};
					}
					outcome = "indexed";
					// The raw value whole, whatever its shape; no lifetime, so it keeps its end.
					const enveloped = { value: kept(value, subject) };
					const shown = keyed
						? mark === undefined
							? witnessed
							: undefined
						: listedWith(mark, space, { key, name: "record" });
					return { targets: [enveloped, shown] };
				},
			});
			if (!changed) return { kind: outcome };
		}
		throw new Unavailable("subject-records");
	};

	let indexed = 0;
	let removed = 0;
	try {
		let cursor: string | undefined;
		let server: string | undefined;
		let started = 0;
		do {
			if (options.signal?.aborted) return stopped("aborted");
			const page = await walk.sweep(space, cursor);
			if (server !== undefined && page.server !== server) {
				// Another server's page continues no walk of this one: start over, as the walk asks.
				started += 1;
				if (started > restarts) return stopped("walk-unsteady");
				server = page.server;
				cursor = undefined;
				continue;
			}
			server = page.server;
			for (const found of page.keys) {
				const key = recordKeyIn(found, space, name);
				if (key === undefined) continue;
				if (options.signal?.aborted) return stopped("aborted");
				const one = await migrated(key);
				if (one.kind === "stopped") return stopped(one.reason);
				if (one.kind === "indexed") indexed += 1;
				if (one.kind === "removed") removed += 1;
			}
			cursor = page.cursor;
		} while (cursor !== undefined);
	} catch (error) {
		if (error instanceof Unavailable) return stopped("unavailable");
		if (error instanceof UnreadableIndex) return stopped("index-unreadable");
		throw error;
	}
	return report({ kind: "migrated", space, indexed, removed });
}

/** The key of a space's record a walk hands back, or none for another space, name or shape. */
function recordKeyIn(found: unknown, space: string, name: string): string | undefined {
	if (typeof found !== "object" || found === null) return undefined;
	const key = found as {
		readonly space?: { readonly name?: unknown };
		partition?: unknown;
		name?: unknown;
	};
	if (key.space?.name !== space || key.name !== name || typeof key.partition !== "string") {
		return undefined;
	}
	return key.partition;
}
