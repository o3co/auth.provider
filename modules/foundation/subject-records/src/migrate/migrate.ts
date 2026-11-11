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
	const listedIn = (mark: Json | undefined, key: string) =>
		keyed
			? mark !== undefined
			: entriesIn(mark, space).some((e) => e.key === key && e.name === "record");

	/**
	 * One record decided in one change, holding it as read beside the marks named: never on reads
	 * alone, which a failover can take back, so a skip and an absence are confirmed as a write is.
	 * `changed` where the record holds another value than `value`, to be read again.
	 */
	const decided = async (
		key: string,
		value: Json | undefined,
		subjects: readonly (string | undefined)[],
		decide: (marks: ReadonlyMap<string, Json | undefined>) => {
			readonly outcome: Done | "todo";
			readonly next?: readonly [Json, string] | "remove";
		},
	): Promise<Done | "todo" | "changed"> => {
		const target: Target = { place, key };
		const named = [...new Set(subjects.filter((one): one is string => one !== undefined))];
		let answer: Done | "todo" | "changed" = "changed";
		await changeRecords({
			targets: [target, ...named.map((one) => markOf(one, key))],
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
				const marks = new Map(named.map((one, at) => [one, read[at]] as const));
				const { outcome, next } = decide(marks);
				answer = outcome;
				if (next === undefined) return {};
				if (next === "remove") return { targets: [{ remove: true }] };
				const subject = next[1];
				const mark = marks.get(subject);
				const shown = keyed
					? mark === undefined
						? witnessed
						: undefined
					: listedWith(mark, space, { key, name: "record" });
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
			const { entry } = await place.store.get(changeRecords.keyOf({ place, key }));
			const value = entry?.value;
			const { subject: shaped } = value === undefined ? {} : opened(value, true);
			/** Whether the record as read is an envelope this package wrote: listed or witnessed. */
			const isOurs = (marks: ReadonlyMap<string, Json | undefined>) =>
				shaped !== undefined && listedIn(marks.get(shaped), key);
			// First, with no owner's reading: a record migrated already, or gone, is decided here.
			const first = await decided(key, value, [shaped], (found) => ({
				outcome: isOurs(found) ? "already" : "todo",
			}));
			if (first === "changed") continue;
			if (first !== "todo") return { kind: first };
			const whose = await subjectOf(key, value as Json);
			if (whose.kind === "unreadable")
				return { kind: "stopped", reason: `unreadable: ${whose.reason}` };
			const subject = whose.kind === "subject" ? whose.subject : undefined;
			if (keyed && subject !== undefined && subject !== key) {
				return { kind: "stopped", reason: "a record keyed by another subject" };
			}
			// Then the owner's answer, the envelope's own mark held too: a run that migrated it meanwhile wins.
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
