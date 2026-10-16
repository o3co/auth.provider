import { contract, extensionPoint } from "@mod/kernel";

/**
 * Plain JSON data only: no undefined, non-finite numbers, dates, class instances or cycles.
 * Stored values come back in canonical form, with the keys of objects sorted.
 */
export type Json =
	| null
	| boolean
	| number
	| string
	| readonly Json[]
	| { readonly [key: string]: Json };

/**
 * no-eviction: never dropped to make room. durable: an acknowledged write survives a crash of the
 * store. replicated: an acknowledged write survives a failover to a replica. confirmed-reads:
 * reads and refusing answers (missing, conflict, exists, limited) are confirmed too, so nothing
 * returned can vanish in a failover. A confirmation costs a wait on each read, so confirmed reads
 * are a guarantee of their own, paid only by spaces whose reads allow something.
 */
export type Guarantee = "no-eviction" | "durable" | "replicated" | "confirmed-reads";

/** A namespace a module declares, with the guarantees its data needs; only declared ones are accepted. */
export interface Space {
	readonly name: string;
	readonly guarantees: readonly Guarantee[];
}

/** Keys in one partition can be written together and read consistently. */
export interface Key {
	readonly space: Space;
	readonly partition: string;
	readonly name: string;
}

/**
 * An entry lives while the store clock is before its expiry time; at that very time it is gone,
 * as is a write whose expiry is already at or before the store's present time.
 */
export type Expiry =
	| { readonly kind: "after"; readonly ms: number }
	| { readonly kind: "at"; readonly at: number }
	| { readonly kind: "never" }
	| { readonly kind: "keep" }
	| { readonly kind: "extend"; readonly ms: number };

export interface WriteOptions {
	readonly expiry: Expiry;
	/** Store-clock time after which the write is refused as late. */
	readonly deadline?: number;
	/**
	 * Resends of the same request with the same mark in the partition get the first answer until
	 * the deadline plus a second of skew, or five minutes and a second without a deadline; a
	 * different request under a used mark is refused.
	 */
	readonly idempotency?: string;
}

/**
 * Opaque; versions are compared for equality only and never repeat for a key. Counters go back on
 * restart, failover or expiry, so a version names which counter of which store; giving versions
 * an order would lose that.
 */
export type Version = string;

export interface Entry {
	readonly value: Json;
	readonly version: Version;
	readonly expiresAt: number | null;
}

export interface Read {
	readonly entry: Entry | null;
	readonly now: number;
}

export type Late = { readonly kind: "late" };
/** A used idempotency mark came with a different request. */
export type Reused = { readonly kind: "reused" };
export type Written = { readonly kind: "written"; readonly version: Version };

export type Condition =
	| { readonly key: Key; readonly version: Version }
	| { readonly key: Key; readonly absent: true };

export type BatchWrite =
	| { readonly key: Key; readonly put: Json; readonly expiry: Expiry }
	| { readonly key: Key; readonly remove: true };

export interface Member {
	readonly member: string;
	readonly score: number;
}

/**
 * In a replicated space, an answer of the written kinds (written, removed, taken, committed,
 * counted, a set change) confirms not only its own write but every state the same store held
 * before it, in any key or partition: confirmation waits for the replicas to reach the point the
 * store had reached, and replication keeps order. A refusing answer writes nothing, so it has
 * nothing to wait for and confirms nothing; an unavailable answer confirms nothing either.
 */
export interface Store {
	get(key: Key): Promise<Read>;
	/** Entries of keys in one partition, read at one instant. */
	getMany(
		keys: readonly Key[],
	): Promise<{ readonly entries: readonly (Entry | null)[]; readonly now: number }>;
	put(key: Key, value: Json, options: WriteOptions): Promise<Written | Late | Reused>;
	putIfAbsent(
		key: Key,
		value: Json,
		options: WriteOptions,
	): Promise<
		Written | Late | Reused | { readonly kind: "exists"; readonly remainingMs: number | null }
	>;
	replaceIf(
		key: Key,
		version: Version,
		value: Json,
		options: WriteOptions,
	): Promise<
		Written | Late | Reused | { readonly kind: "conflict" } | { readonly kind: "missing" }
	>;
	removeIf(
		key: Key,
		expected: { readonly version: Version } | { readonly value: Json },
		options?: Omit<WriteOptions, "expiry">,
	): Promise<
		| { readonly kind: "removed"; readonly old: Entry }
		| Late
		| Reused
		| { readonly kind: "conflict" }
		| { readonly kind: "missing" }
	>;
	/**
	 * Removes and returns the entry; of racing takers exactly one gets it. A resend with the same
	 * mark gets the first answer, so a taker whose reply was lost can still learn it took.
	 */
	take(
		key: Key,
		options?: Omit<WriteOptions, "expiry">,
	): Promise<
		{ readonly kind: "taken"; readonly entry: Entry } | { readonly kind: "missing" } | Late | Reused
	>;
	/** All conditions hold and all writes apply, or nothing applies. Keys share one partition. */
	batch(
		conditions: readonly Condition[],
		writes: readonly BatchWrite[],
		options?: Omit<WriteOptions, "expiry">,
	): Promise<
		| { readonly kind: "committed"; readonly versions: readonly (Version | null)[] }
		| Late
		| Reused
		| { readonly kind: "conflict"; readonly index: number }
	>;
	/** A fixed window counted on the store clock; at the limit nothing is written. */
	count(
		key: Key,
		window: { readonly ms: number; readonly limit: number },
		options?: Omit<WriteOptions, "expiry">,
	): Promise<
		| { readonly kind: "counted"; readonly count: number; readonly resetAt: number }
		| { readonly kind: "limited"; readonly resetAt: number }
		| Late
		| Reused
	>;
	/**
	 * Scores are expiry times on the store clock; a member keeps its highest score. Over the cap
	 * the lowest scores go first, and among equal scores the member first in code point order.
	 */
	setAdd(
		key: Key,
		member: string,
		score: number,
		options: { readonly cap: number; readonly expiry: Expiry },
	): Promise<{ readonly evicted: readonly string[] }>;
	/** Live members in code point order. */
	setMembers(key: Key): Promise<{ readonly members: readonly Member[]; readonly now: number }>;
	setRemove(key: Key, member: string): Promise<void>;
	/** The store clock's present time, the one every expiry and deadline is judged by. */
	now(): Promise<number>;
	/** A page of the space's live value keys (no counter or set) and the cursor on; none when done. */
	// A key written or removed meanwhile may come, or twice, or not; one living through the walk comes.
	scan(
		space: Space,
		cursor?: string,
	): Promise<{ readonly keys: readonly Key[]; readonly cursor?: string }>;
}

export const store = contract<Store>("store");

export const spaces = extensionPoint<Space>("store.spaces", {
	multiplicity: "keyed",
	keyOf: (space) => space.name,
});

export type Decision =
	| { readonly kind: "write"; readonly value: Json; readonly expiry: Expiry }
	| { readonly kind: "remove" }
	| { readonly kind: "keep" };

/**
 * Read, decide with a pure function, write on the version read; on a lost race the function
 * runs again on the new entry, so writes made in between are never overwritten blindly.
 */
export async function mutate(
	target: Store,
	key: Key,
	decide: (current: Entry | null, now: number) => Decision,
	options: { readonly attempts?: number; readonly deadline?: number } = {},
): Promise<
	| { readonly kind: "done"; readonly value: Json | null; readonly version: Version | null }
	| Late
	| { readonly kind: "contended" }
> {
	const limits = options.deadline === undefined ? {} : { deadline: options.deadline };
	const gone = { kind: "done", value: null, version: null } as const;
	for (let attempt = 0; attempt < (options.attempts ?? 8); attempt++) {
		const { entry, now } = await target.get(key);
		const decision = decide(entry, now);
		if (decision.kind === "keep") {
			return entry ? { kind: "done", value: entry.value, version: entry.version } : gone;
		}
		if (decision.kind === "remove") {
			if (!entry) return gone;
			const removed = await target.removeIf(key, { version: entry.version }, limits);
			if (removed.kind === "late") return removed;
			if (removed.kind === "removed" || removed.kind === "missing") return gone;
			continue;
		}
		const writeOptions = { expiry: decision.expiry, ...limits };
		const written = entry
			? await target.replaceIf(key, entry.version, decision.value, writeOptions)
			: await target.putIfAbsent(key, decision.value, writeOptions);
		if (written.kind === "late") return written;
		if (written.kind === "written") {
			return { kind: "done", value: decision.value, version: written.version };
		}
		// exists, conflict or missing: the entry moved since the read; read again.
	}
	return { kind: "contended" };
}

/** Reads a key, then the keys its entry points to, and retries until the first did not move. */
export async function getFollowing(
	target: Store,
	first: Key,
	follow: (entry: Entry | null) => readonly Key[],
	attempts = 8,
): Promise<
	| {
			readonly first: Entry | null;
			readonly followed: readonly (Entry | null)[];
			readonly now: number;
	  }
	| { readonly kind: "contended" }
> {
	for (let attempt = 0; attempt < attempts; attempt++) {
		const head = await target.get(first);
		const keys = follow(head.entry);
		const read = await target.getMany([first, ...keys]);
		const [again, ...followed] = read.entries;
		if ((again?.version ?? null) === (head.entry?.version ?? null)) {
			return { first: again ?? null, followed, now: read.now };
		}
	}
	return { kind: "contended" };
}

const maxTime = 8_640_000_000_000_000;
const maxDepth = 64;

/** One serialization for every implementation: keys sorted, so equal requests read the same. */
export function canonicalJson(value: Json): string {
	if (value === null || typeof value !== "object") return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v as Json)).join(",")}]`;
	const record = value as Record<string, Json>;
	return `{${Object.keys(record)
		.sort()
		.map((k) => `${JSON.stringify(k)}:${canonicalJson(record[k] as Json)}`)
		.join(",")}}`;
}

/** What an idempotency mark is bound to, the same for every implementation. */
export function idempotencyRequest(
	operation: string,
	keys: readonly Key[],
	args: readonly Json[],
): string {
	return canonicalJson([operation, keys.map((k) => [k.space.name, k.partition, k.name]), args]);
}

/** The order of members and of ties: by code point, which is also the order of their UTF-8 bytes. */
export function codePointOrder(a: string, b: string): number {
	return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function fail(message: string): never {
	throw new TypeError(`store: ${message}`);
}

function whole(what: string, value: unknown, min: number, max = maxTime): number {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) {
		fail(`${what} must be an integer in [${min}, ${max}]`);
	}
	return value === 0 ? 0 : value;
}

function text(what: string, value: unknown, max = 512): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > max ||
		!value.isWellFormed()
	) {
		fail(`${what} must be a well-formed, non-empty string of at most ${max} characters`);
	}
	return value;
}

/** Reads the own data properties of a plain object once; nothing read can change afterwards. */
function fields(
	what: string,
	value: unknown,
	allowed?: readonly string[],
): Record<string, unknown> {
	if (value === null || typeof value !== "object" || Array.isArray(value))
		fail(`${what} must be an object`);
	const proto = Object.getPrototypeOf(value);
	if (proto !== Object.prototype && proto !== null) fail(`${what} must be a plain object`);
	if (Object.getOwnPropertySymbols(value).length > 0) fail(`${what} may not have symbol keys`);
	const out: Record<string, unknown> = {};
	for (const [name, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
		if (!("value" in descriptor)) fail(`${what} may not have accessors`);
		if (name === "__proto__") fail(`${what} may not have a __proto__ key`);
		if (!descriptor.enumerable) fail(`${what} may not have hidden properties`);
		if (allowed && !allowed.includes(name)) fail(`${what} has an unknown property ${name}`);
		out[name] = descriptor.value;
	}
	return out;
}

/** Copies a value while checking it is plain JSON data; -0 becomes 0. */
function json(value: unknown, depth = 0): Json {
	if (depth > maxDepth) fail("value nests too deeply");
	if (value === null || typeof value === "boolean") return value;
	if (typeof value === "string") {
		if (!value.isWellFormed()) fail("strings in a value must be well-formed");
		return value;
	}
	if (typeof value === "number") {
		if (!Number.isFinite(value)) fail("numbers in a value must be finite");
		return value === 0 ? 0 : value;
	}
	if (Array.isArray(value)) {
		if (Object.getPrototypeOf(value) !== Array.prototype) fail("arrays in a value must be plain");
		const descriptors = Object.getOwnPropertyDescriptors(value);
		const names = Object.keys(descriptors).filter((name) => name !== "length");
		if (names.length !== value.length || Object.getOwnPropertySymbols(value).length > 0) {
			fail("arrays in a value may hold only their items");
		}
		return names.map((name, index) => {
			const descriptor = descriptors[name];
			if (name !== String(index) || !descriptor || !("value" in descriptor))
				fail("arrays in a value may hold only their items");
			return json(descriptor.value, depth + 1);
		});
	}
	if (typeof value === "object") {
		const read = fields("an object in a value", value);
		const out: Record<string, Json> = {};
		for (const [name, item] of Object.entries(read)) {
			if (!name.isWellFormed()) fail("keys in a value must be well-formed");
			out[name] = json(item, depth + 1);
		}
		return out;
	}
	return fail(`a value may not hold ${typeof value}`);
}

function readExpiry(value: unknown): Expiry {
	const read = fields("expiry", value, ["kind", "ms", "at"]);
	if (read.kind === "after" || read.kind === "extend")
		return { kind: read.kind, ms: whole("expiry ms", read.ms, 1) };
	if (read.kind === "at") return { kind: "at", at: whole("expiry time", read.at, 0) };
	if (read.kind === "never" || read.kind === "keep") return { kind: read.kind };
	return fail("unknown expiry");
}

function readLimits(value: unknown): { deadline?: number; idempotency?: string } {
	if (value === undefined) return {};
	const read = fields("options", value, ["deadline", "idempotency"]);
	return {
		...(read.deadline === undefined ? {} : { deadline: whole("deadline", read.deadline, 0) }),
		...(read.idempotency === undefined
			? {}
			: { idempotency: text("idempotency mark", read.idempotency) }),
	};
}

function readWriteOptions(value: unknown): WriteOptions {
	const read = fields("options", value, ["expiry", "deadline", "idempotency"]);
	return {
		...readLimits({ deadline: read.deadline, idempotency: read.idempotency }),
		expiry: readExpiry(read.expiry),
	};
}

function readSetOptions(value: unknown): { cap: number; expiry: Expiry } {
	const read = fields("options", value, ["cap", "expiry"]);
	return { cap: whole("cap", read.cap, 0, 1_000_000), expiry: readExpiry(read.expiry) };
}

function readWindow(value: unknown): { ms: number; limit: number } {
	const read = fields("window", value, ["ms", "limit"]);
	return {
		ms: whole("window ms", read.ms, 1),
		limit: whole("limit", read.limit, 0, 1_000_000_000),
	};
}

function readExpected(value: unknown): { version: Version } | { value: Json } {
	const read = fields("expected", value, ["version", "value"]);
	if ("version" in read) return { version: text("version", read.version) };
	return { value: json(read.value) };
}

function readCondition(value: unknown, key: (value: unknown) => Key): Condition {
	const read = fields("condition", value, ["key", "version", "absent"]);
	const k = key(read.key);
	if ("version" in read) return { key: k, version: text("version", read.version) };
	if (read.absent === true) return { key: k, absent: true };
	return fail("a condition needs a version or absent: true");
}

function readBatchWrite(value: unknown, key: (value: unknown) => Key): BatchWrite {
	const read = fields("write", value, ["key", "put", "expiry", "remove"]);
	const k = key(read.key);
	if (read.remove === true) return { key: k, remove: true };
	return { key: k, put: json(read.put), expiry: readExpiry(read.expiry) };
}

/** Checks every input once, the same way for every implementation: read once into plain data,
 * keys in declared spaces, and a whole batch before anything is written. */
export function checkedStore(inner: Store, declared: readonly Space[]): Store {
	const known = new Map(declared.map((space) => [space.name, space]));
	const key = (value: unknown): Key => {
		const read = fields("key", value, ["space", "partition", "name"]);
		const name = text("space", fields("space", read.space, ["name", "guarantees"]).name);
		const space = known.get(name);
		if (!space) fail(`space ${name} is not declared`);
		return {
			space,
			partition: text("partition", read.partition),
			name: text("key name", read.name),
		};
	};
	const batchWrites = (writes: readonly BatchWrite[]) => {
		const checked = [...writes].map((w) => readBatchWrite(w, key));
		const names = checked.map((w) =>
			JSON.stringify([w.key.space.name, w.key.partition, w.key.name]),
		);
		if (new Set(names).size !== names.length) fail("a batch may write each key once");
		return checked;
	};
	return {
		get: async (k) => inner.get(key(k)),
		getMany: async (keys) => inner.getMany([...keys].map(key)),
		put: async (k, v, o) => inner.put(key(k), json(v), readWriteOptions(o)),
		putIfAbsent: async (k, v, o) => inner.putIfAbsent(key(k), json(v), readWriteOptions(o)),
		replaceIf: async (k, version, v, o) =>
			inner.replaceIf(key(k), text("version", version), json(v), readWriteOptions(o)),
		removeIf: async (k, expected, o) =>
			inner.removeIf(key(k), readExpected(expected), readLimits(o)),
		take: async (k, o) => inner.take(key(k), readLimits(o)),
		batch: async (conditions, writes, o) =>
			inner.batch(
				[...conditions].map((c) => readCondition(c, key)),
				batchWrites(writes),
				readLimits(o),
			),
		count: async (k, window, o) => inner.count(key(k), readWindow(window), readLimits(o)),
		setAdd: async (k, member, score, o) =>
			inner.setAdd(key(k), text("member", member), whole("score", score, 0), readSetOptions(o)),
		setMembers: async (k) => inner.setMembers(key(k)),
		scan: async (target, cursor) => {
			const name = text("space", fields("space", target, ["name", "guarantees"]).name);
			const declaredSpace = known.get(name);
			if (!declaredSpace) fail(`space ${name} is not declared`);
			return inner.scan(declaredSpace, cursor === undefined ? undefined : text("cursor", cursor));
		},
		setRemove: async (k, member) => inner.setRemove(key(k), text("member", member)),
		now: () => inner.now(),
	};
}
