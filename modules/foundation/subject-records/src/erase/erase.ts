import type { SpaceReport } from "@mod/erasure-extensions";
import { Unavailable } from "@mod/kernel";
import { changeRecords, type Next, type Target } from "@mod/records";
import type { Json } from "@mod/store";
import { opened } from "../envelope/envelope.ts";
import { indexOver, keysIn, type SubjectPlace } from "../index/index.ts";

/** Keys settled in one write: their records and sets, and the bucket listing them. */
const perBatch = 32;

/** The one place a report is made; nothing outside this package makes one. */
const report = (made: { kind: string; space: string } & Record<string, unknown>) =>
	made as unknown as SpaceReport;

/** What to do with one key: remove its record, its set, and take it out of the bucket. */
interface Settled {
	readonly record: boolean;
	readonly set: boolean;
	readonly leaves: boolean;
}

/**
 * Settles `keys` of a space as one write, by what their record and set hold: each removed as
 * `settle` says, and those leaving taken out of `bucket`, which goes with its last key. Answers the
 * records and sets removed that were held, and the keys that left.
 */
async function settled(
	place: SubjectPlace,
	bucket: Target | undefined,
	keys: readonly string[],
	settle: (record: Json | undefined, set: Json | undefined) => Settled,
) {
	const names = keys.flatMap((key): Target[] => [
		{ place, key },
		{ place, key, set: true },
	]);
	let answer = { removed: 0, left: 0 };
	await changeRecords({
		targets: bucket ? [bucket, ...names] : names,
		decide: (read) => {
			const [listed, ...held] = bucket ? read : [undefined, ...read];
			const next: Next<Json>[] = [];
			const leaving = new Set<string>();
			let removed = 0;
			keys.forEach((key, at) => {
				const [record, set] = [held[2 * at], held[2 * at + 1]];
				const one = settle(record, set);
				next.push(
					one.record ? { remove: true } : undefined,
					one.set ? { remove: true } : undefined,
				);
				removed +=
					(one.record && record !== undefined ? 1 : 0) + (one.set && set !== undefined ? 1 : 0);
				if (one.leaves) leaving.add(key);
			});
			answer = { removed, left: leaving.size };
			if (!bucket) return { targets: next };
			const rest = keysIn(listed).filter((k) => !leaving.has(k));
			const kept: Next<Json> =
				leaving.size === 0
					? undefined
					: rest.length > 0
						? { value: rest, lifetimeMs: "endless" }
						: { remove: true };
			return { targets: [kept, ...next] };
		},
	});
	return answer;
}

/**
 * Erases a subject from one space (account erasure §3.2): writes its tombstone, where none stands,
 * then removes what the subject holds there. In a space declaring `online-indexed`, the records and
 * sets its buckets list, those whose envelope names it, each key leaving its bucket with them; in
 * one declaring `online-keyed`, those under `keys`, which its owner makes from the subject; in one
 * declaring `bounded`, nothing: its records end by the tombstone's time and the space's `boundedMs`.
 * A record or set read absent is removed all the same, so no expired one stays held. Stops between
 * writes where `signal` aborts; the tombstone stands, and erasing again finishes.
 */
export async function eraseSubject(
	place: SubjectPlace,
	subject: string,
	options: { readonly keys?: readonly string[]; readonly signal?: AbortSignal } = {},
): Promise<SpaceReport> {
	const category = place.space.subjectData;
	const space = place.space.name;
	if (category !== "online-indexed" && category !== "online-keyed" && category !== "bounded") {
		throw new TypeError(`subject-records: ${space} declares no category erased here`);
	}
	if ((category === "online-keyed") !== (options.keys !== undefined)) {
		throw new TypeError("subject-records: keys are given for a space declaring online-keyed alone");
	}
	if (category === "bounded" && place.space.boundedMs === undefined) {
		throw new TypeError(`subject-records: ${space} declares bounded with no boundedMs`);
	}
	const stopped = (reason: string) => report({ kind: "stopped", space, reason });
	if (place.phase !== "indexed") return stopped("not-indexed");
	const { tombOf, bucketsOf } = indexOver(place, place.space, place.index);
	const theirs = (held: Json | undefined) => held === undefined || opened(held).subject === subject;
	const settle = (record: Json | undefined, set: Json | undefined): Settled => ({
		record: theirs(record),
		set: theirs(set),
		leaves: true,
	});
	try {
		if (options.signal?.aborted) return stopped("aborted");
		// The tombstone's time bounds its commit on the store clock, as a write commits by its deadline.
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
			return report({ kind: "fenced", space, until: at + (place.space.boundedMs ?? 0) });
		}
		let removed = 0;
		if (category === "online-keyed") {
			const keys = options.keys ?? [];
			for (let from = 0; from < keys.length; from += perBatch) {
				if (options.signal?.aborted) return stopped("aborted");
				removed += (await settled(place, undefined, keys.slice(from, from + perBatch), settle))
					.removed;
			}
			return report({ kind: "erased", space, removed });
		}
		for (const bucket of bucketsOf(subject)) {
			for (;;) {
				if (options.signal?.aborted) return stopped("aborted");
				const { entry } = await place.store.get(changeRecords.keyOf(bucket));
				const keys = keysIn(entry?.value).slice(0, perBatch);
				if (keys.length === 0) break;
				removed += (await settled(place, bucket, keys, settle)).removed;
			}
		}
		return report({ kind: "erased", space, removed });
	} catch (error) {
		if (error instanceof Unavailable) return stopped("unavailable");
		throw error;
	}
}

/**
 * A page of a space's index, as `store` scans it: each key its buckets list whose record and set
 * both read absent is removed, so no expired one stays held, and leaves its bucket as one. A key
 * whose record or set lives stays. Answers the keys that left, and where to go on.
 */
export async function sweepIndex(
	place: SubjectPlace,
	cursor?: string,
): Promise<{ readonly swept: number; readonly cursor?: string }> {
	const { entryAt } = indexOver(place, place.space, place.index);
	const name = changeRecords.keyOf(entryAt("")).name;
	const page = await place.store.scan(place.index, cursor);
	let swept = 0;
	const absent = (record: Json | undefined, set: Json | undefined): Settled => {
		const gone = record === undefined && set === undefined;
		return { record: gone, set: gone, leaves: gone };
	};
	for (const key of page.keys) {
		if (key.name !== name || !/\.m[0-9a-f]$/.test(key.partition)) continue;
		const bucket = entryAt(key.partition);
		const keys = keysIn((await place.store.get(key)).entry?.value);
		for (let from = 0; from < keys.length; from += perBatch) {
			swept += (await settled(place, bucket, keys.slice(from, from + perBatch), absent)).left;
		}
	}
	return page.cursor === undefined ? { swept } : { swept, cursor: page.cursor };
}
