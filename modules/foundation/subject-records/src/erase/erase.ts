import type { SpaceReport } from "@mod/erasure-extensions";
import { Unavailable } from "@mod/kernel";
import { changeRecords, type Next, type Target } from "@mod/records";
import type { Json } from "@mod/store";
import { opened } from "../envelope/envelope.ts";
import {
	checkedSubjectPlace,
	type Entry,
	entriesIn,
	indexOver,
	listedWithout,
	type SubjectPlace,
	targetOf,
	UnreadableIndex,
} from "../index/index.ts";

/** Entries settled in one write: their records and sets, and the bucket listing them. */
const perBatch = 32;

/**
 * What a bounded space's fence allows for the store's clock stepping back between a record's
 * creation and its subject's tombstone: 5 minutes, fixed, as hosts' clocks are kept synchronized
 * (docs/security-model.md, what the deployment does) and a step past it is an operator's fault.
 */
export const clockAllowanceMs = 5 * 60_000;

/** The one place a report is made; nothing outside this package makes one. */
const report = (made: { kind: string; space: string } & Record<string, unknown>) =>
	made as unknown as SpaceReport;

/** What to do with one entry: remove what it names, and take it out of its bucket. */
interface Settled {
	readonly remove: boolean;
	readonly leaves: boolean;
}

/**
 * Settles `entries` of a space as one write, each by what it names holds: removed as `settle`
 * says, those leaving taken out of `bucket`, which goes with its last entry. Every target is held
 * as read. Answers what was removed that was held, and the entries that left.
 */
async function settled(
	place: SubjectPlace,
	bucket: Target | undefined,
	entries: readonly Entry[],
	settle: (held: Json | undefined) => Settled,
) {
	let answer = { removed: 0, left: 0 };
	await changeRecords({
		targets: [...(bucket ? [bucket] : []), ...entries.map((e) => targetOf(place, e))],
		decide: (read) => {
			const [listed, ...held] = bucket ? read : [undefined, ...read];
			const leaving = new Set<Entry>();
			let removed = 0;
			const next = entries.map((entry, at): Next<Json> => {
				const one = settle(held[at]);
				if (one.leaves) leaving.add(entry);
				if (!one.remove) return undefined;
				if (held[at] !== undefined) removed += 1;
				return { remove: true };
			});
			answer = { removed, left: leaving.size };
			if (!bucket) return { targets: next };
			const left = listedWithout(listed, place.space.name, (e) =>
				[...leaving].some((l) => l.key === e.key && l.name === e.name),
			);
			return { targets: [left, ...next] };
		},
	});
	return answer;
}

/**
 * Erases a subject from one space (account erasure §3.2): writes its tombstone, where none stands,
 * then removes what the subject holds there. In a space declaring `online-indexed`, what its
 * buckets list where it reads absent or its envelope names the subject, each entry leaving its
 * bucket as it goes; in one declaring `online-keyed`, the record and the set under the subject
 * itself; in one declaring `bounded`, nothing: its records end by the tombstone's deadline, the
 * space's `boundedMs` and the clock allowance. Stops between writes where `signal` aborts; the
 * tombstone stands, and erasing again finishes. A place the builders would refuse throws TypeError.
 */
export async function eraseSubject(
	place: SubjectPlace,
	subject: string,
	options: { readonly signal?: AbortSignal } = {},
): Promise<SpaceReport> {
	const category = checkedSubjectPlace(
		place,
		["online-indexed", "online-keyed", "bounded"],
		"subject-records",
		(_, reason) => {
			throw new TypeError(`subject-records: ${place.space.name}: ${reason}`);
		},
	);
	const space = place.space.name;
	const boundedMs = place.space.boundedMs;
	if (category === "bounded" && boundedMs === undefined) {
		throw new TypeError(`subject-records: ${space} declares bounded with no boundedMs`);
	}
	const stopped = (reason: string) => report({ kind: "stopped", space, reason });
	if (place.phase !== "indexed") return stopped("not-indexed");
	const { tombOf, bucketsOf } = indexOver(place, place.space, place.index);
	try {
		if (options.signal?.aborted) return stopped("aborted");
		// The tombstone's deadline bounds its commit on the store clock, as a write commits by its deadline.
		let at: number | undefined;
		await changeRecords({
			targets: [tombOf(subject)],
			decide: ([tomb], _, attempt) => {
				if (tomb !== undefined) {
					const standing = (tomb as { at?: unknown }).at;
					at = typeof standing === "number" ? standing : undefined;
					return {};
				}
				at = attempt.deadline;
				return { targets: [{ value: { at: attempt.deadline }, lifetimeMs: "endless" }] };
			},
		});
		if (category === "bounded") {
			if (at === undefined) return stopped("tombstone-unreadable");
			const until = at + (boundedMs ?? 0) + clockAllowanceMs;
			return report({ kind: "fenced", space, until });
		}
		if (options.signal?.aborted) return stopped("aborted");
		if (category === "online-keyed") {
			// Keyed by the subject itself, whatever is under it is the subject's.
			const under: Entry[] = [
				{ key: subject, name: "record" },
				{ key: subject, name: "set" },
			];
			const { removed } = await settled(place, undefined, under, () => ({
				remove: true,
				leaves: true,
			}));
			return report({ kind: "erased", space, removed });
		}
		const theirs = (held: Json | undefined): Settled => ({
			remove: held === undefined || opened(held, true).subject === subject,
			leaves: true,
		});
		let removed = 0;
		for (const bucket of bucketsOf(subject)) {
			for (;;) {
				if (options.signal?.aborted) return stopped("aborted");
				const { entry } = await place.store.get(changeRecords.keyOf(bucket));
				const entries = entriesIn(entry?.value, space).slice(0, perBatch);
				if (entries.length === 0) break;
				removed += (await settled(place, bucket, entries, theirs)).removed;
			}
		}
		return report({ kind: "erased", space, removed });
	} catch (error) {
		if (error instanceof Unavailable) return stopped("unavailable");
		if (error instanceof UnreadableIndex) return stopped("index-unreadable");
		throw error;
	}
}

/**
 * A page of a space's index, as `store` scans it: each entry its buckets list whose record or set
 * reads absent is removed, so no expired one stays held, and leaves its bucket as one; an entry
 * whose record or set lives stays. Answers the entries that left, and where to go on.
 */
export async function sweepIndex(
	place: SubjectPlace,
	cursor?: string,
): Promise<{ readonly swept: number; readonly cursor?: string }> {
	const { entryAt } = indexOver(place, place.space, place.index);
	const name = changeRecords.keyOf(entryAt("")).name;
	const page = await place.store.scan(place.index, cursor);
	const absent = (held: Json | undefined): Settled => ({
		remove: held === undefined,
		leaves: held === undefined,
	});
	let swept = 0;
	for (const key of page.keys) {
		if (key.name !== name || !/\.m[0-9a-f]$/.test(key.partition)) continue;
		const entries = entriesIn((await place.store.get(key)).entry?.value, place.space.name);
		for (let from = 0; from < entries.length; from += perBatch) {
			const batch = entries.slice(from, from + perBatch);
			swept += (await settled(place, entryAt(key.partition), batch, absent)).left;
		}
	}
	return page.cursor === undefined ? { swept } : { swept, cursor: page.cursor };
}
