import { BuildRefused, contract, extensionPoint } from "@mod/kernel";
import { malformedDeclaration } from "./declaration.ts";

export {
	type Control,
	type Honours,
	type KeptSpace,
	type Mark,
	type StoreControl,
	type StoreUpkeep,
	storeControl,
	storeUpkeep,
	type UpkeepImplementation,
} from "./upkeep/upkeep.ts";

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

/**
 * What a space holds of a subject's data, as its owner declares it for erasing an account, which
 * reads it. To store, each is opaque but `none` (`noSubjectData`) and the four a change reaches only
 * carrying the subject writer (`checks`).
 */
export type SubjectData =
	| "online-indexed"
	| "online-keyed"
	| "bounded"
	| "window"
	| "none"
	| "pseudonymous"
	| "retained"
	| "internal";

/**
 * The categories a change reaches only carrying the subject writer (`checks`): subjects' data, and an
 * index of it. A subset of `SubjectData` by construction; a name it misspells drops out, and the
 * tables held to it then fail to compile.
 */
export type WriterHeld = Extract<
	SubjectData,
	"online-indexed" | "online-keyed" | "bounded" | "internal"
>;

/** The space holds no subject's data; any other category may hold some. */
export const noSubjectData = "none" satisfies SubjectData;

/** A namespace a module declares, with the guarantees its data needs; only declared ones are accepted. */
export interface Space {
	readonly name: string;
	readonly guarantees: readonly Guarantee[];
	/** What it holds of a subject's data, named by every declaration (one without it refuses the boot). Erasure's word, carried on the declaration for erasure to read, and for store to ask the subject writer of a change. */
	readonly subjectData: SubjectData;
	/** The eraser that erases it, by its key, for erasure to find. */
	readonly erasedBy?: string;
	/** For a bounded space: the longest a record lives from its creation, in ms. */
	readonly boundedMs?: number;
	/** Once erasure is enabled, every process must declare it to start (the control record's `requires`). */
	readonly requiredOnceErasing?: boolean;
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
	 * the deadline plus a second of skew, or five minutes and a second without a deadline
	 * (`idempotencyWindows`); a different request under a used mark is refused.
	 */
	readonly idempotency?: string;
}

declare const subjectWriterBrand: unique symbol;
/**
 * What a change to a space holding subjects' data carries, so a store can tell a change of
 * `subject-records` from anything else. Its one value is `@mod/store/subject-writer`'s, which the
 * manifest's `takenBy` keeps for `subject-records`. It is no boundary against a deployment's own code.
 */
export type SubjectWriter = { readonly [subjectWriterBrand]: true };

/** A batch's options: its deadline and mark, and the subject writer where it changes subjects' data. */
export type BatchOptions = Omit<WriteOptions, "expiry"> & { readonly writer?: SubjectWriter };

/** How long every store keeps an idempotency mark, in ms: past its deadline, or from now without one; then past that too. */
export const idempotencyWindows = Object.freeze({
	withoutDeadlineMs: 300_000,
	pastDeadlineMs: 1000,
});

/**
 * Opaque, compared for equality only, never repeating for a key. Counters go back on restart,
 * failover or expiry, so a version names which counter of which store, and has no order.
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

/**
 * A batch's writes applied: each version (none for a removal), and the store time it committed at;
 * a resend under its mark answers the first commit's.
 */
export type Committed = {
	readonly kind: "committed";
	readonly versions: readonly (Version | null)[];
	readonly at: number;
};

/**
 * In a replicated space, a written answer (written, removed, taken, committed, counted) confirms
 * every state the same store held before it, in any key or partition, as replication keeps order.
 * A refusing answer writes nothing and confirms nothing; an unavailable answer confirms nothing.
 */
export interface Store {
	get(key: Key): Promise<Read>;
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
	/** Removes and returns the entry, to exactly one of racing takers; a resend under its mark learns it took. */
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
		options?: BatchOptions,
	): Promise<Committed | Late | Reused | { readonly kind: "conflict"; readonly index: number }>;
	/**
	 * As `batch`, over keys of any partition, and of any spaces declaring the same guarantees. Its
	 * mark binds the request (its keys in their order) and is kept, with one answer and one end, in
	 * every partition it touches, the partitions it only reads included: a resend meets it in any, and
	 * another request meeting it in any is reused. A late answer is not kept. Reads made before it are
	 * no snapshot: a value relied on goes in as a condition. A store without it leaves it out.
	 */
	batchAcross?(
		conditions: readonly Condition[],
		writes: readonly BatchWrite[],
		options?: BatchOptions,
	): Promise<Committed | Late | Reused | { readonly kind: "conflict"; readonly index: number }>;
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
	 * Reads of several keys, each as `get` reads one, in the order asked: at one store time where the
	 * store is one server, else each at its own. A store without it leaves it out.
	 */
	getMany?(keys: readonly Key[]): Promise<readonly Read[]>;
	/** The store clock's present time, the one every expiry and deadline is judged by. */
	now(): Promise<number>;
	/** A page of the space's live value keys (no counter) and the cursor on; none when done. */
	// Any key may come twice; one living through the walk comes unless a failover or restart falls in it.
	scan(
		space: Space,
		cursor?: string,
	): Promise<{ readonly keys: readonly Key[]; readonly cursor?: string }>;
}

export const store = contract<Store>("store");

export const spaces = extensionPoint<Space>("store.spaces", {
	multiplicity: "keyed",
	// A declaration keys by its own data `name`, read with no getter run. One with none (no object,
	// no such name, a getter, or a proxy trap that throws as the name is read) is refused here, as it
	// is collected; a named but malformed one, by store's checks as the store is built.
	keyOf: (space) => {
		let named: unknown;
		try {
			named =
				typeof space === "object" && space !== null
					? Object.getOwnPropertyDescriptor(space, "name")?.value
					: undefined;
		} catch {
			named = undefined;
		}
		if (typeof named !== "string")
			throw new BuildRefused("store.declaration", malformedDeclaration);
		return named;
	},
});

export type Decision =
	| { readonly kind: "write"; readonly value: Json; readonly expiry: Expiry }
	| { readonly kind: "remove" }
	| { readonly kind: "keep" };

/** How many times `mutate` reads and decides again after losing a race, unless its caller says. */
const defaultAttempts = 8;

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
	for (let attempt = 0; attempt < (options.attempts ?? defaultAttempts); attempt++) {
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
