/** What a leg is told by: a report's or a mark's entry and its shard. */
interface Leg {
	readonly identity: { readonly entry: string; readonly shard?: string };
}

/** What choosing a report reads: its leg, and the commit, run, target, attempt and job it was made in. */
interface Report extends Leg {
	readonly identity: Leg["identity"] & {
		readonly commit: string;
		readonly run: string;
		readonly target: string;
		readonly attempt: number;
		readonly job: string;
	};
}

/** A leg of an entry: its shard (`i/n`), or the whole entry, a report or mark without one or `1/1`. */
export const legOf = (entry: string, shard: string | undefined) =>
	JSON.stringify([entry, shard === undefined || shard === "1/1" ? "" : shard]);

/** A report's shard, `[i, n]`; none for one that ran its entry whole. */
const shardOf = (r: Leg): readonly [number, number] | undefined => {
	const m = /^(\d+)\/(\d+)$/.exec(r.identity.shard ?? "");
	return m && Number(m[2]) > 1 ? [Number(m[1]), Number(m[2])] : undefined;
};

/**
 * The legs a kind of job runs: each matrix value once, as many times as its runs have shards, each
 * with its shard (`i/n`, `1/1` for one). Runs sharing a value that disagree on their shards are refused.
 */
export function legsOf(
	runs: readonly { readonly kind: string; readonly matrix?: string; readonly shards?: number }[],
	kind: string,
) {
	const shards = new Map<string, number>();
	for (const r of runs.filter((r) => r.kind === kind && r.matrix !== undefined)) {
		const value = r.matrix ?? "";
		const n = r.shards ?? 1;
		if ((shards.get(value) ?? n) !== n)
			throw new Error(`${value}: its runs disagree on their shards`);
		shards.set(value, n);
	}
	return [...shards].flatMap(([matrix, n]) =>
		Array.from({ length: n }, (_, i) => ({ matrix, shard: `${i + 1}/${n}` })),
	);
}

/**
 * Which expected runs reported, and which did not: a run is reported by a report of it whole, or by
 * one of each of its shards; one missing a shard is named with it (`<entry> (shard i/n)`). A report
 * of a shard of another count than its run's is not among the reports.
 */
export function reportedOf<R extends Leg>(
	reports: readonly R[],
	expected: {
		readonly entries: readonly string[];
		readonly shards: ReadonlyMap<string, number>;
	},
) {
	const counted = reports.filter((r) => {
		const shard = shardOf(r);
		return shard === undefined || shard[1] === (expected.shards.get(r.identity.entry) ?? 1);
	});
	const present = new Set<string>();
	const missing: string[] = [];
	for (const entry of expected.entries) {
		const of = counted.filter((r) => r.identity.entry === entry);
		const n = expected.shards.get(entry) ?? 1;
		const ran = new Set(of.map((r) => shardOf(r)?.[0] ?? "whole"));
		const left = Array.from({ length: n }, (_, k) => k + 1).filter((i) => !ran.has(i));
		if (ran.has("whole") || (of.length > 0 && left.length === 0)) present.add(entry);
		else if (of.length === 0) missing.push(entry);
		else missing.push(...left.map((i) => `${entry} (shard ${i}/${n})`));
	}
	return { reports: counted, present, missing };
}

/** A job's mark that it was attempted, written before it can fail: the run, the attempt, and the runs it makes. */
export interface Attempted {
	readonly attempted: {
		readonly run: string;
		readonly attempt: number;
		readonly job: string;
		readonly kind: string;
		readonly matrix?: string;
		/** The leg's shard (`i/n`); none for a job that runs the whole. */
		readonly shard?: string;
	};
}

/** The last attempt of this run that each entry's leg was marked attempted in, by the runs the marks name. */
export function attemptsOf(
	marks: readonly Attempted[],
	runs: readonly { readonly entry: string; readonly kind: string; readonly matrix?: string }[],
	run: string,
) {
	const last = new Map<string, number>();
	for (const { attempted: a } of marks.filter((m) => m.attempted.run === run)) {
		const named = runs.filter((r) => r.kind === a.kind && r.matrix === a.matrix);
		for (const r of named) {
			const leg = legOf(r.entry, a.shard);
			last.set(leg, Math.max(last.get(leg) ?? 0, a.attempt));
		}
	}
	return last;
}

/**
 * Of the reports given, this commit's and run's for the new system, every report of each leg and
 * job's last attempt, and none older than the last attempt its leg was marked in: a leg that failed
 * before it reported leaves its earlier attempt's evidence behind, and another leg's stands. A run's
 * whole and its shards cover each other: a mark of the whole holds every shard's reports to it, a
 * shard's mark holds a whole report to it, and of whole and shard reports the later form stands.
 */
export function selectReports<R extends Report>(
	reports: readonly R[],
	of: { readonly commit: string; readonly run: string },
	attempted: ReadonlyMap<string, number> = new Map(),
): R[] {
	const whole = (r: R) =>
		legOf(r.identity.entry, r.identity.shard) === legOf(r.identity.entry, undefined);
	const marked = (entry: string) =>
		[...attempted].filter(([leg]) => JSON.parse(leg)[0] === entry).map(([, at]) => at);
	const floorOf = (r: R) =>
		whole(r)
			? Math.max(0, ...marked(r.identity.entry))
			: Math.max(
					attempted.get(legOf(r.identity.entry, r.identity.shard)) ?? 0,
					attempted.get(legOf(r.identity.entry, undefined)) ?? 0,
				);
	const ours = reports.filter(
		(r) =>
			r.identity.commit === of.commit &&
			r.identity.run === of.run &&
			r.identity.target === "new" &&
			r.identity.attempt >= floorOf(r),
	);
	const keyOf = (r: R) =>
		JSON.stringify([legOf(r.identity.entry, r.identity.shard), r.identity.job]);
	const lastAttempt = new Map<string, number>();
	const latest = new Map<string, number>();
	for (const r of ours) {
		lastAttempt.set(keyOf(r), Math.max(lastAttempt.get(keyOf(r)) ?? 0, r.identity.attempt));
		const form = JSON.stringify([r.identity.entry, whole(r)]);
		latest.set(form, Math.max(latest.get(form) ?? 0, r.identity.attempt));
	}
	// Every report of its leg's last attempt, two processes of one leg, job and attempt both, and
	// none older than the latest report of the run's other form.
	return ours.filter(
		(r) =>
			r.identity.attempt === lastAttempt.get(keyOf(r)) &&
			r.identity.attempt >= (latest.get(JSON.stringify([r.identity.entry, !whole(r)])) ?? 0),
	);
}
