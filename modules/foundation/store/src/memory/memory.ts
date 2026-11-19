import { BuildRefused, deepFreeze, type Runtime, Unavailable } from "@mod/kernel";
import { checkedStore, checkedUpkeep, declaredSpaces } from "../checks/checks.ts";
import {
	type BatchWrite,
	type Condition,
	canonicalJson,
	type Entry,
	type Expiry,
	idempotencyRequest,
	idempotencyWindows,
	type Json,
	type KeptPage,
	type Key,
	type Late,
	type Mark,
	noSubjectData,
	type Reused,
	type Space,
	type Store,
	type StoreControl,
	type StoreUpkeep,
	type UpkeepImplementation,
} from "../contract.ts";

type Answer = { readonly kind: string };
type Held = { readonly value: Json; readonly version: string; readonly expiresAt: number | null };
type Limits = { readonly deadline?: number; readonly idempotency?: string } | undefined;

const { withoutDeadlineMs: idempotencyDefaultMs, pastDeadlineMs: idempotencySkewMs } =
	idempotencyWindows;
const sweepEvery = 256;
const scanPage = 100;

const id = (key: Key) => JSON.stringify([key.space.name, key.partition, key.name]);
const partitionOf = (key: Key) => JSON.stringify([key.space.name, key.partition]);
/** The space a value's or counter's id names, and the space an idempotency mark's partition names. */
const spaceOfId = (at: string) => (JSON.parse(at) as [string])[0];
const spaceOfMark = (mark: string) => spaceOfId((JSON.parse(mark) as [string])[0]);
/** What a kept space's walk meets: a value, a counter or an idempotency answer. */
type Family = "value" | "counter" | "answer";
/** Expired at exactly its expiry, for reads and writes alike, so the two agree at that instant. */
const live = (held: { expiresAt: number | null } | undefined, now: number) =>
	held !== undefined && (held.expiresAt === null || held.expiresAt > now);

/** Expiry for a new write given the entry's current expiry (undefined when there is none). */
export function resolveExpiry(
	expiry: Expiry,
	current: number | null | undefined,
	now: number,
): number | null {
	switch (expiry.kind) {
		case "after":
			return now + expiry.ms;
		case "at":
			return expiry.at;
		case "never":
			return null;
		case "keep":
			return current ?? null;
		case "extend":
			if (current === null) return null;
			return Math.max(current ?? 0, now + expiry.ms);
	}
}

function entryOf(held: Held): Entry {
	return deepFreeze({
		value: structuredClone(held.value),
		version: held.version,
		expiresAt: held.expiresAt,
	});
}

/** Counts versions from one, never naming one twice within the store. */
const counting = () => {
	let last = 0;
	return () => String(++last);
};

/** Counts the data opened in this process, so each names itself apart in `sweep`'s answers. */
let dataOpened = 0;

/** A store's data in memory, which one process or more opens (`memoryProcess`). */
export interface MemoryData {
	readonly clock: Runtime["clock"];
	readonly nextVersion: () => string;
	/** Names each new epoch, never one the data had: nothing outlives the data, so a count will do. */
	readonly nextEpoch: () => string;
	readonly values: Map<string, Held>;
	readonly counters: Map<string, { count: number; resetAt: number }>;
	readonly answers: Map<string, { digest: string; answer: Answer; until: number }>;
	/** Each space ever declared: whether a declaration may have held a subject's data, and its generation. */
	readonly ledger: Map<string, { readonly subjectDataEver: boolean; readonly generation: string }>;
	/** Names each declaration added to the ledger, never one the data had. */
	readonly nextGeneration: () => string;
	/** Counts each walk of a kept space, never one the data had: with the data's name, its handle, a cursor holding no key. */
	readonly nextWalk: () => string;
	readonly control: {
		epoch: string | null;
		maintenance: boolean;
		requires: readonly string[];
		readonly marks: Map<string, Mark>;
	};
	/** Names the data as `sweep` answers it, apart from other data in the process. */
	readonly server: string;
	/** The processes open on the data: each joins once it has started, and leaves when detached. */
	readonly processes: Set<object>;
	operations: number;
}

/** Fresh data; `nextVersion` names each written version, by default from its own count. */
export function memoryData(
	clock: Runtime["clock"],
	nextVersion: () => string = counting(),
): MemoryData {
	return {
		clock,
		nextVersion,
		nextEpoch: counting(),
		values: new Map(),
		counters: new Map(),
		answers: new Map(),
		ledger: new Map(),
		nextGeneration: counting(),
		nextWalk: counting(),
		control: { epoch: null, maintenance: false, requires: [], marks: new Map() },
		server: `memory-${++dataOpened}`,
		processes: new Set(),
		operations: 0,
	};
}

/** A store in memory, over data of its own. */
export function memoryStore(
	clock: Runtime["clock"],
	declared: readonly Space[],
	nextVersion: () => string = counting(),
): Store {
	return memoryProcess(memoryData(clock, nextVersion), declared).store;
}

/** A store in memory, over data of its own, whose ports check nothing: for a store a caller checks itself. */
export function memoryCore(
	clock: Runtime["clock"],
	declared: readonly Space[],
	nextVersion: () => string = counting(),
): Store {
	return memoryProcess(memoryData(clock, nextVersion), declared).unchecked;
}

/**
 * Refuses a start the control record forbids, as a boot refusal, before anything is written: under
 * the maintenance key unless the process may build under it; without a space `requires` names
 * unless it may build under the key and is under it (a tool replacing `requires` may not compose one).
 */
function refusedStart(
	record: MemoryData["control"],
	declared: readonly Space[],
	mayBuildUnderKey: boolean,
): void {
	if (record.maintenance && !mayBuildUnderKey) {
		throw new BuildRefused(
			"store",
			"only a tool may start while the store is under the maintenance key",
		);
	}
	const names = new Set(declared.map((space) => space.name));
	const missing = record.requires.filter((name) => !names.has(name));
	if (missing.length > 0 && !(mayBuildUnderKey && record.maintenance)) {
		// Store's own fixed text: a required name is the data's, and no refusal carries it.
		throw new BuildRefused("store", "the data requires a space this process does not declare");
	}
}

/**
 * A process over `data`: as it starts it checks its declarations, reads the control record once,
 * refusing a start that read forbids and taking its epoch from it, and only then adds its spaces to
 * the ledger; each change it makes once the record's epoch is another is unavailable.
 */
export function memoryProcess(
	data: MemoryData,
	declared: readonly Space[],
	/** Whether the process may build under the maintenance key, as its composition grants (a tool's). */
	mayBuildUnderKey = false,
): {
	readonly store: Store;
	readonly unchecked: Store;
	readonly control: StoreControl;
	readonly upkeep: StoreUpkeep;
	/** Leaves the data's registry of processes. */
	readonly detach: () => void;
} {
	const { clock, nextVersion, values, counters, answers, ledger, control: record } = data;
	let taken = record.epoch;
	/** Whether this process took its epoch under the maintenance key: it changes only while the key is held. */
	let keyed = record.maintenance;
	/** Whether the process has detached: stopped for good, each change and read it makes unavailable. */
	let detached = false;
	const refuseDetached = () => {
		if (detached) throw new Unavailable("store");
	};
	/** Refuses a change once the process detached, the record's epoch is not the one it took, or its key has lifted. */
	const refuseStale = () => {
		refuseDetached();
		if (record.epoch !== taken) throw new Unavailable("store");
		if (keyed && !record.maintenance) throw new Unavailable("store");
	};
	// Refused before anything is written: a malformed declaration, then the control record's two.
	declaredSpaces(declared);
	refusedStart(record, declared, mayBuildUnderKey);
	for (const space of declared) {
		// Every declaration added is a new generation, the entry's `subjectDataEver` kept.
		ledger.set(space.name, {
			subjectDataEver:
				(ledger.get(space.name)?.subjectDataEver ?? false) || space.subjectData !== noSubjectData,
			generation: data.nextGeneration(),
		});
	}
	const known = new Set(declared.map((space) => space.name));
	/** This process in the data's registry, which it joins once started (below), and leaves when detached. */
	const self = {};

	const sweep = (now: number) => {
		if (++data.operations % sweepEvery !== 0) return;
		for (const [k, v] of values) if (!live(v, now)) values.delete(k);
		for (const [k, v] of answers) if (v.until <= now) answers.delete(k);
		for (const [k, v] of counters) if (v.resetAt <= now) counters.delete(k);
	};
	/** The value held at `key` while it lives, removing it once expired: for a change, which is fenced. */
	const current = (key: Key, now: number) => {
		const held = values.get(id(key));
		if (live(held, now)) return held;
		values.delete(id(key));
		return undefined;
	};
	/** The value held at `key` while it lives, for a read: a read changes nothing, an expired value left held. */
	const seen = (key: Key, now: number) => {
		const held = values.get(id(key));
		return live(held, now) ? held : undefined;
	};
	/**
	 * A batch at `now`, as one: every condition checked first, the first not met answered by its
	 * index with nothing written; else every write made, each version (none for a removal) answered.
	 */
	const applyBatch = (
		conditions: readonly Condition[],
		writes: readonly BatchWrite[],
		now: number,
	) => {
		for (const [index, condition] of conditions.entries()) {
			const held = current(condition.key, now);
			const holds = "absent" in condition ? !held : held?.version === condition.version;
			if (!holds) return { kind: "conflict" as const, index };
		}
		const versions = writes.map((w) => {
			if ("remove" in w) {
				values.delete(id(w.key));
				return null;
			}
			return write(w.key, w.put, w.expiry, now);
		});
		return { kind: "committed" as const, versions, at: now };
	};
	/** Runs a write once per idempotency mark and request, refusing it after its deadline. */
	const guarded = async <A extends Answer>(
		partition: string | undefined,
		request: string,
		options: Limits,
		apply: (now: number) => A,
	): Promise<A | Late | Reused> => {
		refuseStale();
		const now = clock.now();
		sweep(now);
		const mark =
			partition && options?.idempotency && JSON.stringify([partition, options.idempotency]);
		if (mark) {
			const seen = answers.get(mark);
			if (seen && seen.until > now)
				return seen.digest === request ? (seen.answer as A) : { kind: "reused" };
		}
		const late = options?.deadline !== undefined && now > options.deadline;
		const answer = late
			? deepFreeze({ kind: "late" as const })
			: deepFreeze(structuredClone(apply(now)));
		if (mark) {
			const until = (options?.deadline ?? now + idempotencyDefaultMs) + idempotencySkewMs;
			answers.set(mark, { digest: request, answer, until });
		}
		return answer;
	};
	/**
	 * Runs a batch across partitions once per mark and request: the mark is looked for in every
	 * partition first, kept in each with one answer and one end, never rewritten when reused, and a
	 * late answer is not kept.
	 */
	const guardedAcross = async <A extends Answer>(
		partitions: readonly string[],
		request: string,
		options: Limits,
		apply: (now: number) => A,
	): Promise<A | Late | Reused> => {
		refuseStale();
		const now = clock.now();
		sweep(now);
		const marks = options?.idempotency
			? partitions.map((partition) => JSON.stringify([partition, options.idempotency]))
			: [];
		for (const mark of marks) {
			const seen = answers.get(mark);
			if (seen && seen.until > now)
				return seen.digest === request ? (seen.answer as A) : { kind: "reused" };
		}
		if (options?.deadline !== undefined && now > options.deadline) return { kind: "late" };
		const answer = deepFreeze(structuredClone(apply(now)));
		const until = (options?.deadline ?? now + idempotencyDefaultMs) + idempotencySkewMs;
		for (const mark of marks) answers.set(mark, { digest: request, answer, until });
		return answer;
	};
	const write = (key: Key, value: Json, expiry: Expiry, now: number) => {
		const before = current(key, now);
		const version = nextVersion();
		const expiresAt = resolveExpiry(expiry, before ? before.expiresAt : undefined, now);
		if (expiresAt !== null && expiresAt <= now) values.delete(id(key));
		else values.set(id(key), { value: JSON.parse(canonicalJson(value)), version, expiresAt });
		return version;
	};
	const samePartition = (keys: readonly Key[]) => {
		if (new Set(keys.map(partitionOf)).size > 1)
			throw new Error("keys span more than one partition");
	};

	/** A page of the space's live value keys after `cursor`, and the cursor on where more remain. */
	const pageOf = (space: Space, cursor: string | undefined, now: number) => {
		const ids = [...values]
			.filter(([at, held]) => live(held, now) && JSON.parse(at)[0] === space.name)
			.map(([at]) => at)
			.filter((at) => cursor === undefined || at > cursor)
			.sort();
		const page = ids.slice(0, scanPage);
		const keys = page.map((at) => {
			const [, partition, name] = JSON.parse(at) as [string, string, string];
			return { space, partition, name };
		});
		const last = page.at(-1);
		return ids.length > scanPage && last ? { keys, cursor: last } : { keys };
	};
	/** A kept space's walk this process holds, by its handle: at most one per space (`walkOf`). */
	const walks = new Map<
		string,
		{ readonly name: string; readonly keys: readonly (readonly [Family, string])[]; at: number }
	>();
	const walkOf = new Map<string, string>();
	/**
	 * A page of a kept space's walk: the keys of the space its first page took, met in turn, each
	 * expired one removed and the rest counted; its cursor a handle, never a key. A new walk of the
	 * space drops this process's earlier one; a walk ends with its last page.
	 */
	const keptPage = (name: string, cursor: string | undefined, generation: string): KeptPage => {
		const now = clock.now();
		let handle = cursor;
		if (handle === undefined) {
			const earlier = walkOf.get(name);
			if (earlier !== undefined) walks.delete(earlier);
			handle = `${data.server}.walk-${data.nextWalk()}`;
			walks.set(handle, { name, keys: keysOfSpace(name), at: 0 });
			walkOf.set(name, handle);
		}
		const walk = walks.get(handle) as NonNullable<ReturnType<typeof walks.get>>;
		const page = walk.keys.slice(walk.at, walk.at + scanPage);
		walk.at += page.length;
		let count = 0;
		let noExpiry = 0;
		let latest: number | undefined;
		const met = (end: number | null) => {
			count += 1;
			if (end === null) noExpiry += 1;
			else latest = latest === undefined ? end : Math.max(latest, end);
		};
		for (const [family, key] of page) {
			if (family === "value") {
				const held = values.get(key);
				if (held && live(held, now)) met(held.expiresAt);
				else values.delete(key);
			} else if (family === "counter") {
				const held = counters.get(key);
				if (held && held.resetAt > now) met(held.resetAt);
				else counters.delete(key);
			} else {
				const held = answers.get(key);
				if (held && held.until > now) met(held.until);
				else answers.delete(key);
			}
		}
		const done = walk.at >= walk.keys.length;
		if (done) {
			walks.delete(handle);
			walkOf.delete(name);
		}
		return {
			kind: "page",
			live: count,
			noExpiry,
			...(latest === undefined ? {} : { latestExpiry: latest }),
			...(cursor === undefined ? { generation } : {}),
			...(done ? {} : { cursor: handle }),
			server: data.server,
		};
	};
	/** Every key a kept space holds now: its values, counters and idempotency answers. */
	const keysOfSpace = (name: string): (readonly [Family, string])[] => [
		...[...values.keys()].filter((k) => spaceOfId(k) === name).map((k) => ["value", k] as const),
		...[...counters.keys()]
			.filter((k) => spaceOfId(k) === name)
			.map((k) => ["counter", k] as const),
		...[...answers.keys()]
			.filter((k) => spaceOfMark(k) === name)
			.map((k) => ["answer", k] as const),
	];
	const readControl: StoreControl = {
		control: async () => {
			refuseDetached();
			return deepFreeze({
				epoch: record.epoch,
				maintenance: record.maintenance,
				requires: [...record.requires],
				marks: Object.fromEntries(
					[...record.marks].map(([name, mark]) => [name, structuredClone(mark)]),
				),
			});
		},
	};
	// The memory store gives what one process holds: nothing lost to eviction, every read confirmed.
	const unmet: Record<string, string> = {
		durable: "memory loses everything on restart",
		replicated: "memory has no replica",
	};
	const upkeep: UpkeepImplementation = {
		mark: async (name, value) => {
			refuseStale();
			record.marks.set(name, { value: JSON.parse(canonicalJson(value)), epoch: record.epoch });
			return { kind: "marked" };
		},
		require: async (names) => {
			refuseStale();
			if (!record.maintenance) return { kind: "not-in-maintenance" };
			record.requires = [...names];
			return { kind: "required" };
		},
		enterMaintenance: async () => {
			refuseStale();
			const epoch = data.nextEpoch();
			record.epoch = epoch;
			record.maintenance = true;
			taken = epoch;
			keyed = true;
			return { kind: "entered", epoch };
		},
		leaveMaintenance: async () => {
			refuseStale();
			record.maintenance = false;
			return { kind: "left" };
		},
		alone: async () => {
			refuseDetached();
			const others = data.processes.size - (data.processes.has(self) ? 1 : 0);
			return deepFreeze(others === 0 ? { kind: "alone" } : { kind: "accompanied", count: others });
		},
		kept: async () => {
			refuseDetached();
			return deepFreeze(
				[...ledger].map(([name, entry]) => ({ name, subjectDataEver: entry.subjectDataEver })),
			);
		},
		// One uninterrupted step: the fences, the key, this process's declarations, the entry and its generation.
		retire: async (name, generation) => {
			refuseStale();
			if (!record.maintenance) return { kind: "not-in-maintenance" };
			if (known.has(name)) return { kind: "declared" };
			const entry = ledger.get(name);
			if (entry === undefined) return { kind: "missing" };
			if (entry.generation !== generation) return { kind: "redeclared" };
			ledger.delete(name);
			return { kind: "retired" };
		},
		sweepKept: async (name, cursor) => {
			// A cursor is a walk this process holds of this space, or a caller's error, before anything else.
			if (cursor !== undefined && walks.get(cursor)?.name !== name) {
				throw new TypeError("store: the cursor is no walk of this space that this process holds");
			}
			refuseStale();
			if (!record.maintenance) return { kind: "not-in-maintenance" };
			if (known.has(name)) return { kind: "declared" };
			const entry = ledger.get(name);
			if (entry === undefined) return { kind: "missing" };
			return deepFreeze(keptPage(name, cursor, entry.generation));
		},
		honours: async (guarantees) => {
			refuseDetached();
			const reasons = guarantees.flatMap((g) => (unmet[g] ? [unmet[g]] : []));
			return deepFreeze(
				reasons.length > 0
					? { kind: "unmet", reasons }
					: { kind: "verified", witness: data.server },
			);
		},
		sweep: async (space, cursor) => {
			refuseStale();
			const now = clock.now();
			for (const [at, held] of values) {
				if (!live(held, now) && JSON.parse(at)[0] === space.name) values.delete(at);
			}
			return deepFreeze({ ...pageOf(space, cursor, now), server: data.server });
		},
	};

	/** Its ports with no check of their own: `checkedStore` checks every input once, as below, or over a store a caller checks itself (`simulated`). */
	const unchecked: Store = {
		get: async (key) => {
			refuseDetached();
			const now = clock.now();
			const held = seen(key, now);
			return { entry: held ? entryOf(held) : null, now };
		},
		getMany: async (keys) => {
			refuseDetached();
			const now = clock.now();
			return deepFreeze(
				keys.map((key) => {
					const held = seen(key, now);
					return { entry: held ? entryOf(held) : null, now };
				}),
			);
		},
		putIfAbsent: (key, value, options) =>
			guarded(
				partitionOf(key),
				idempotencyRequest("putIfAbsent", [key], [value, options.expiry]),
				options,
				(now) => {
					const held = current(key, now);
					if (held) {
						return {
							kind: "exists" as const,
							remainingMs: held.expiresAt === null ? null : held.expiresAt - now,
						};
					}
					return { kind: "written" as const, version: write(key, value, options.expiry, now) };
				},
			),
		replaceIf: (key, version, value, options) =>
			guarded(
				partitionOf(key),
				idempotencyRequest("replaceIf", [key], [version, value, options.expiry]),
				options,
				(now) => {
					const held = current(key, now);
					if (!held) return { kind: "missing" as const };
					if (held.version !== version) return { kind: "conflict" as const };
					return { kind: "written" as const, version: write(key, value, options.expiry, now) };
				},
			),
		removeIf: (key, expected, options) =>
			guarded(
				partitionOf(key),
				idempotencyRequest("removeIf", [key], [expected]),
				options,
				(now) => {
					const held = current(key, now);
					if (!held) return { kind: "missing" as const };
					const matches =
						"version" in expected
							? held.version === expected.version
							: canonicalJson(held.value) === canonicalJson(expected.value);
					if (!matches) return { kind: "conflict" as const };
					values.delete(id(key));
					return { kind: "removed" as const, old: entryOf(held) };
				},
			),
		take: (key, options) =>
			guarded(partitionOf(key), idempotencyRequest("take", [key], []), options, (now) => {
				const held = current(key, now);
				if (!held) return { kind: "missing" as const };
				values.delete(id(key));
				return { kind: "taken" as const, entry: entryOf(held) };
			}),
		batchAcross: async (conditions, writes, options) => {
			const keys = [...conditions.map((c) => c.key), ...writes.map((w) => w.key)];
			const request = idempotencyRequest("batchAcross", keys, [
				conditions.map((c) => ("absent" in c ? { absent: true } : { version: c.version })),
				writes.map((w) => ("remove" in w ? null : [w.put, w.expiry])),
			]);
			const partitions = [...new Set(keys.map(partitionOf))];
			return guardedAcross(partitions, request, options, (now) =>
				applyBatch(conditions, writes, now),
			);
		},
		batch: async (conditions, writes, options) => {
			const keys = [...conditions.map((c) => c.key), ...writes.map((w) => w.key)];
			samePartition(keys);
			const request = idempotencyRequest("batch", keys, [
				conditions.map((c) => ("absent" in c ? { absent: true } : { version: c.version })),
				writes.map((w) => ("remove" in w ? null : [w.put, w.expiry])),
			]);
			return guarded(keys[0] && partitionOf(keys[0]), request, options, (now) =>
				applyBatch(conditions, writes, now),
			);
		},
		count: (key, window, options) =>
			guarded(
				partitionOf(key),
				idempotencyRequest("count", [key], [window.ms, window.limit]),
				options,
				(now) => {
					const held = counters.get(id(key));
					if (!held || held.resetAt <= now) {
						if (window.limit < 1) return { kind: "limited" as const, resetAt: now + window.ms };
						counters.set(id(key), { count: 1, resetAt: now + window.ms });
						return { kind: "counted" as const, count: 1, resetAt: now + window.ms };
					}
					if (held.count >= window.limit)
						return { kind: "limited" as const, resetAt: held.resetAt };
					held.count += 1;
					return { kind: "counted" as const, count: held.count, resetAt: held.resetAt };
				},
			),
		now: async () => {
			refuseDetached();
			return clock.now();
		},
		scan: async (space, cursor) => {
			refuseDetached();
			return deepFreeze(pageOf(space, cursor, clock.now()));
		},
	};
	const store = checkedStore(unchecked, declared);
	const checked = checkedUpkeep(upkeep, declared);
	// Joins only once every part is built, so a process that did not start is never counted.
	data.processes.add(self);
	return {
		store,
		unchecked,
		control: readControl,
		upkeep: checked,
		// Stopped first, so no process the registry no longer counts can still run an operation.
		detach: () => {
			detached = true;
			// Its walks go with it: no key a snapshot took stays held by a process that has stopped.
			walks.clear();
			walkOf.clear();
			data.processes.delete(self);
		},
	};
}
