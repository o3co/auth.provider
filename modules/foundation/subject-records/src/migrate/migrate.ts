import type {
	Elsewhere,
	MigrationReport,
	SetReading,
	SubjectOf,
	SubjectReading,
	Walk,
} from "@mod/erasure-extensions";
import { type Clock, Unavailable } from "@mod/kernel";
import { changeRecords, keyedSetsIn, type Target } from "@mod/records";
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

/** Where a migration makes its report; only this package makes one, here and in internal module `erase`. */
const report = (made: { kind: string; space: string } & Record<string, unknown>) =>
	made as unknown as MigrationReport;

/** Reads of one record before it is unavailable, where its value keeps changing between a read and its write. */
const rereads = 8;
/** Times a walk starts over, its server changing, before the space stops. */
const restarts = 8;

/** What a decision on one record came to. */
type Done = "indexed" | "removed" | "already" | "gone";
/** What one record came to. */
type Outcome = { readonly kind: Done } | { readonly kind: "stopped"; readonly reason: string };

/**
 * Puts the records of one space written before indexing into its index, once records are indexed
 * (account erasure §5.1): each raw record its owner's `subjectOf` reads as a subject's is kept in
 * an envelope with that subject, listed in its bucket (`online-indexed`) or written with its
 * witness (`online-keyed`), its value and its end as they were; each it proves an orphan is
 * removed; one it cannot read stops the space, removing nothing more. A record is already migrated
 * only where its envelope is listed or witnessed, never by its shape alone, so a rerun, a key a
 * walk meets twice, and two runs at once each index or remove a record once. Each write holds the
 * record as read. A `bounded` space has nothing to index. Keyed sets: `migrateSets`.
 * Stops between records where `signal` aborts; running again finishes. Where `elsewhere` is given,
 * it runs for each orphan on the value a confirmed change held, before the removal, which still
 * holds that value: a record changed meanwhile is read again and the step run again; a throw stops
 * the space, removing nothing more.
 */
export async function migrateRecords(
	place: SubjectPlace,
	walk: Walk,
	subjectOf: SubjectReading,
	options: { readonly signal?: AbortSignal; readonly elsewhere?: Elsewhere } = {},
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
	if (place.phase !== "indexed") return report({ kind: "stopped", space, reason: "not-indexed" });
	if (category === "bounded") return report({ kind: "migrated", space, indexed: 0, removed: 0 });
	const how: Migrating = { entry: "record", read: subjectOf };
	return migrating(place, walk, category === "online-keyed", how, options);
}

/**
 * Puts the keyed sets of one `online-indexed` space kept raw before indexing into its index, as
 * `migrateRecords` does records, with these differences: each set is read strictly first
 * (`records`' codec), and one with any malformed part stops the space, removing nothing more; the
 * owner reads its subject from the key alone (`SetReading`); an indexed set is its raw value whole
 * in an envelope, both lists and every member's end as they were, nothing rebuilt and no cap
 * applied again, keeping its end; an orphan is removed, with no step elsewhere first. An
 * `online-keyed` space has none to index: erasing a subject removes what is under its key, raw or
 * not, and the next add puts it in its envelope.
 */
export async function migrateSets(
	place: SubjectPlace & { readonly cap: number; readonly clock: Clock },
	walk: Walk,
	reading: SetReading,
	options: { readonly signal?: AbortSignal } = {},
): Promise<MigrationReport> {
	const category = checkedSubjectPlace(
		place,
		["online-indexed", "online-keyed"],
		"subject-records",
		(_, reason) => {
			throw new TypeError(`subject-records: ${place.space.name}: ${reason}`);
		},
	);
	const space = place.space.name;
	if (place.phase !== "indexed") return report({ kind: "stopped", space, reason: "not-indexed" });
	if (category === "online-keyed")
		return report({ kind: "migrated", space, indexed: 0, removed: 0 });
	const codec = keyedSetsIn.codec(place);
	const how: Migrating = {
		entry: "set",
		check: (value) => {
			const read = codec.strict(value);
			return read.kind === "unreadable" ? read.reason : undefined;
		},
		read: (key) => reading(key),
	};
	return migrating(place, walk, false, how, options);
}

/** What one migration walks: records or sets, how each is read, and its owner's step for an orphan. */
interface Migrating {
	readonly entry: "record" | "set";
	/** Why a value cannot be read as one of its kind, or none; a reason stops the space. */
	readonly check?: (value: Json | undefined) => string | undefined;
	readonly read: (key: string, value: Json) => Promise<SubjectOf>;
}

/** The one walk both migrations take, over an indexed `online-*` space. */
async function migrating(
	place: SubjectPlace,
	walk: Walk,
	keyed: boolean,
	how: Migrating,
	options: { readonly signal?: AbortSignal; readonly elsewhere?: Elsewhere },
): Promise<MigrationReport> {
	const space = place.space.name;
	const stopped = (reason: string) => report({ kind: "stopped", space, reason });
	const { bucketOf, witnessOf } = indexOver(place, place.space, place.index);
	const targetOf = (key: string): Target =>
		how.entry === "set" ? { place, key, set: true } : { place, key };
	const name = changeRecords.keyOf(targetOf("")).name;
	/** What proves an envelope of `subject` at `key` this package's own: its bucket entry, or its witness. */
	const provenanceOf = (subject: string, key: string): Target =>
		keyed ? witnessOf(subject, how.entry) : bucketOf(subject, key);
	const provenIn = (proof: Json | undefined, key: string) =>
		keyed
			? proof !== undefined
			: entriesIn(proof, space).some((e) => e.key === key && e.name === how.entry);

	/**
	 * One record decided in one change, holding it as read beside the provenance named: never on reads
	 * alone, which a failover can take back, so a skip and an absence are confirmed as a write is.
	 * `changed` where the record holds another value than `value`, to be read again.
	 */
	const decided = async (
		key: string,
		value: Json | undefined,
		subjects: readonly (string | undefined)[],
		decide: (proofs: ReadonlyMap<string, Json | undefined>) => {
			readonly outcome: Done | "todo";
			readonly next?: readonly [Json, string] | "remove";
		},
	): Promise<Done | "todo" | "changed"> => {
		const target = targetOf(key);
		const named = [...new Set(subjects.filter((one): one is string => one !== undefined))];
		let answer: Done | "todo" | "changed" = "changed";
		await changeRecords({
			targets: [target, ...named.map((one) => provenanceOf(one, key))],
			decide: ([held, ...read]) => {
				if (
					held === undefined
						? value !== undefined
						: canonicalJson(held) !== canonicalJson(value ?? null)
				) {
					answer = "changed";
					return {};
				}
				if (held === undefined) {
					answer = "gone";
					return {};
				}
				const proofs = new Map(named.map((one, at) => [one, read[at]] as const));
				const { outcome, next } = decide(proofs);
				answer = outcome;
				if (next === undefined) return {};
				if (next === "remove") return { targets: [{ remove: true }] };
				const subject = next[1];
				const proof = proofs.get(subject);
				const shown = keyed
					? proof === undefined
						? witnessed
						: undefined
					: listedWith(proof, space, { key, name: how.entry });
				// The raw value whole, whatever its shape; no lifetime, so it keeps its end.
				return {
					targets: [
						{ value: next[0] },
						...named.map((one) => (one === subject ? shown : undefined)),
					],
				};
			},
		});
		return answer;
	};

	const migrated = async (key: string): Promise<Outcome> => {
		for (let read = 0; read < rereads; read += 1) {
			const { entry } = await place.store.get(changeRecords.keyOf(targetOf(key)));
			const value = entry?.value;
			const { subject: shaped } = value === undefined ? {} : opened(value, true);
			/** Whether the record as read is an envelope this package wrote: listed or witnessed. */
			const isOurs = (proofs: ReadonlyMap<string, Json | undefined>) =>
				shaped !== undefined && provenIn(proofs.get(shaped), key);
			// First, with no owner's reading: a record migrated already, or gone, is decided here.
			const first = await decided(key, value, [shaped], (found) => ({
				outcome: isOurs(found) ? "already" : "todo",
			}));
			if (first === "changed") continue;
			if (first !== "todo") return { kind: first };
			const unread = value === undefined ? undefined : how.check?.(value);
			if (unread !== undefined) return { kind: "stopped", reason: `unreadable: ${unread}` };
			const whose = await how.read(key, value as Json);
			if (whose.kind === "unreadable")
				return { kind: "stopped", reason: `unreadable: ${whose.reason}` };
			const subject = whose.kind === "subject" ? whose.subject : undefined;
			if (keyed && subject !== undefined && subject !== key) {
				return { kind: "stopped", reason: `a ${how.entry} keyed by another subject` };
			}
			// An orphan's owner keeps what it holds elsewhere first, from the value the first change confirmed.
			if (subject === undefined && options.elsewhere !== undefined) {
				try {
					await options.elsewhere(key, value);
				} catch (error) {
					return { kind: "stopped", reason: `elsewhere: ${typeOf(error)}` };
				}
			}
			// Then the owner's answer, the envelope's own provenance held too: a run that migrated it meanwhile wins.
			const outcome = await decided(key, value, [subject, shaped], (found) => {
				if (isOurs(found)) return { outcome: "already" };
				if (subject === undefined) return { outcome: "removed", next: "remove" };
				return { outcome: "indexed", next: [kept(value as Json, subject), subject] };
			});
			if (outcome === "changed") continue;
			if (outcome === "todo") throw new Error("subject-records: a migration decided nothing");
			return { kind: outcome };
		}
		throw new Unavailable("subject-records");
	};

	let indexed = 0;
	let removed = 0;
	try {
		let cursor: string | undefined;
		let server: string | undefined;
		let started = 0;
		// Ends only after a page is taken with no cursor on: a start-over goes round again from the first page.
		for (;;) {
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
			if (cursor === undefined) break;
		}
	} catch (error) {
		if (error instanceof Unavailable) return stopped("unavailable");
		if (error instanceof UnreadableIndex) return stopped("index-unreadable");
		throw error;
	}
	return report({ kind: "migrated", space, indexed, removed });
}

const typeOf = (error: unknown) => (error instanceof Error ? error.name : typeof error);

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
