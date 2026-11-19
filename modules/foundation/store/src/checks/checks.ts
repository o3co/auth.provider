import { BuildRefused } from "@mod/kernel";
import type {
	BatchWrite,
	Condition,
	Expiry,
	Guarantee,
	Json,
	Key,
	Space,
	Store,
	SubjectData,
	Version,
	WriteOptions,
	WriterHeld,
} from "../contract.ts";
import { malformedDeclaration } from "../declaration.ts";
import type { KeptSpace } from "../ledger/ledger.ts";
import type { Alone, Honours, StoreUpkeep, UpkeepImplementation } from "../upkeep/upkeep.ts";
import { subjectWriter } from "../writer/subject-writer.ts";

const maxTime = 8_640_000_000_000_000;
const maxDepth = 64;

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

/**
 * `WriterHeld`, as a table: a fresh literal so the compiler holds it to `WriterHeld` both ways; no
 * spread, `as` or intermediate.
 */
const writerHeld = {
	"online-indexed": true,
	"online-keyed": true,
	bounded: true,
	internal: true,
} satisfies Record<WriterHeld, true>;
/** Whether a key's declared space is one a change reaches only carrying the subject writer. */
const heldByWriter = (k: Key) =>
	k.space.subjectData !== undefined && Object.hasOwn(writerHeld, k.space.subjectData);

/** A key a single-key change port takes: none in a space held by the writer, which no such port carries. */
function unheld(k: Key): Key {
	if (heldByWriter(k))
		fail(`a change to ${k.space.name} goes in a batch carrying the subject writer`);
	return k;
}

/**
 * A batch's options: checked whole as plain data first, the writer allowed among them; then the
 * subject writer checked by its identity, and asked for where any key read or written (`keys`) is in
 * a space held by it; then taken off, so the store below never sees it.
 */
function readBatchOptions(
	value: unknown,
	keys: readonly Key[],
): { deadline?: number; idempotency?: string } {
	const read =
		value === undefined ? {} : fields("options", value, ["deadline", "idempotency", "writer"]);
	if (read.writer !== undefined && read.writer !== subjectWriter)
		fail("a batch's writer is not the subject writer");
	const held = keys.find(heldByWriter);
	if (read.writer === undefined && held !== undefined)
		fail(`a change to ${held.space.name} carries the subject writer`);
	return readLimits({ deadline: read.deadline, idempotency: read.idempotency });
}

function readWriteOptions(value: unknown): WriteOptions {
	const read = fields("options", value, ["expiry", "deadline", "idempotency"]);
	return {
		...readLimits({ deadline: read.deadline, idempotency: read.idempotency }),
		expiry: readExpiry(read.expiry),
	};
}

/**
 * The longest cursor taken back: longer than any a store gives, as memory's names a whole key
 * (three texts of 512 characters, each escaped to at most 6) and Redis's is a number.
 */
const cursorLength = 16_384;

/** The largest count a window may allow. */
const largestLimit = 1_000_000_000;

function readWindow(value: unknown): { ms: number; limit: number } {
	const read = fields("window", value, ["ms", "limit"]);
	return {
		ms: whole("window ms", read.ms, 1),
		limit: whole("limit", read.limit, 0, largestLimit),
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

/** Every `SubjectData`, as a table: a fresh literal so the compiler holds it to `SubjectData` both ways; no spread, `as` or intermediate. */
const subjectDataKinds = {
	"online-indexed": true,
	"online-keyed": true,
	bounded: true,
	window: true,
	none: true,
	pseudonymous: true,
	retained: true,
	internal: true,
} satisfies Record<SubjectData, true>;
const spaceFields = [
	"name",
	"guarantees",
	"subjectData",
	"erasedBy",
	"boundedMs",
	"requiredOnceErasing",
];
/** Every `Guarantee`, as a table, held to the type both ways as `subjectDataKinds` is. */
const guaranteeKinds = {
	"no-eviction": true,
	durable: true,
	replicated: true,
	"confirmed-reads": true,
} satisfies Record<Guarantee, true>;
const isGuarantee = (g: unknown): g is Guarantee =>
	typeof g === "string" && Object.hasOwn(guaranteeKinds, g);

/** Whether `value` is a plain list of known guarantees, each own data entry read through its descriptor: no getter or method of it run. */
function knownGuarantees(value: unknown): boolean {
	if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return false;
	const length = Object.getOwnPropertyDescriptor(value, "length");
	if (!length || !("value" in length)) return false;
	// The indices and `length`, nothing else: no own method or iterator a reader would call.
	if (Reflect.ownKeys(value).length !== length.value + 1) return false;
	for (let i = 0; i < length.value; i++) {
		const entry = Object.getOwnPropertyDescriptor(value, String(i));
		if (!entry || !("value" in entry) || !isGuarantee(entry.value)) return false;
	}
	return true;
}

/**
 * Refuses the boot over a malformed declaration (kernel's `BuildRefused`), naming its space; the
 * reason is store's own fixed text, never what the declaration holds. Port input is a `TypeError`.
 */
function refusedDeclaration(space: unknown, reason: string): never {
	const named =
		typeof space === "object" && space !== null
			? Object.getOwnPropertyDescriptor(space, "name")?.value
			: undefined;
	let refused: BuildRefused;
	try {
		// Kernel bounds a `where` (one printable line of 1 to 200 characters); store bounds a name otherwise.
		refused = new BuildRefused(typeof named === "string" ? named : "store.declaration", reason);
	} catch {
		refused = new BuildRefused("store.declaration", reason);
	}
	throw refused;
}

/** Whether `check` runs without throwing: any throw, a `TypeError` or a proxy trap's, reads as no. */
const takes = (check: () => unknown) => {
	try {
		check();
		return true;
	} catch {
		return false;
	}
};

/** The declared spaces by name, each declaration's own fields checked for their shape alone; a malformed one refuses the boot. */
export function declaredSpaces(declared: readonly Space[]): ReadonlyMap<string, Space> {
	for (const space of declared) {
		let read: Record<string, unknown> = {};
		const plain = takes(() => {
			read = fields("space", space, spaceFields);
			text("space", read.name);
		});
		if (!plain) {
			refusedDeclaration(space, malformedDeclaration);
		}
		if (read.subjectData === undefined) refusedDeclaration(space, "declares no subjectData");
		if (typeof read.subjectData !== "string" || !Object.hasOwn(subjectDataKinds, read.subjectData))
			refusedDeclaration(space, "declares an unknown subjectData");
		if (read.erasedBy !== undefined && !takes(() => text("erasedBy", read.erasedBy)))
			refusedDeclaration(space, "declares an erasedBy that is no well-formed name");
		if (read.boundedMs !== undefined && !takes(() => whole("boundedMs", read.boundedMs, 1)))
			refusedDeclaration(space, "declares a boundedMs that is no whole number of ms of 1 or more");
		if (read.requiredOnceErasing !== undefined && typeof read.requiredOnceErasing !== "boolean")
			refusedDeclaration(space, "declares a requiredOnceErasing that is no boolean");
		let listed = false;
		takes(() => {
			// Kernel freezes a declaration one level deep, so its list is frozen here, as checked.
			if (knownGuarantees(read.guarantees))
				listed = Object.isFrozen(Object.freeze(read.guarantees));
		});
		if (!listed)
			refusedDeclaration(space, "declares guarantees that are no list of known guarantees");
	}
	return new Map(declared.map((space) => [space.name, space]));
}

/** The declared space a value names. */
function spaceIn(known: ReadonlyMap<string, Space>, value: unknown): Space {
	const name = text("space", fields("space", value, spaceFields).name);
	const space = known.get(name);
	if (!space) fail(`space ${name} is not declared`);
	return space;
}

/** The declared space `name` names; any other name is a caller's error. */
function declaredNamed(known: ReadonlyMap<string, Space>, name: unknown): Space {
	const space = known.get(text("space", name));
	if (!space) fail(`space ${String(name)} is not declared`);
	return space;
}

/** `alone()`'s answer where the implementation offers no way to look. */
const noLookOffered: Alone = Object.freeze({
	kind: "unchecked",
	reasons: Object.freeze(["no-look-offered"]),
});

/** Checks upkeep's input once, as `checkedStore` checks the store's: names, values and spaces. */
export function checkedUpkeep(
	inner: UpkeepImplementation,
	declared: readonly Space[],
): StoreUpkeep {
	const known = declaredSpaces(declared);
	const ordered = Object.freeze([...declared]);
	return {
		declared: () => ordered,
		// Where the implementation offers no way to look, store's own code: never `alone` in doubt.
		alone: inner.alone?.bind(inner) ?? (async () => noLookOffered),
		mark: async (name, value) => inner.mark(text("mark name", name), json(value)),
		require: async (names) => {
			if (!Array.isArray(names) || names.length === 0) fail("require needs one space or more");
			return inner.require([...new Set([...names].map((n) => text("space", n)))]);
		},
		enterMaintenance: () => inner.enterMaintenance(),
		leaveMaintenance: () => inner.leaveMaintenance(),
		kept: (): Promise<readonly KeptSpace[]> => inner.kept(),
		retire: async (name) => inner.retire(text("space", name)),
		honours: async (asked): Promise<Honours> => {
			if (!Array.isArray(asked)) fail("guarantees must be a list");
			for (const g of asked) if (!isGuarantee(g)) fail(`unknown guarantee ${String(g)}`);
			return inner.honours([...new Set(asked)]);
		},
		sweep: async (name, cursor) =>
			inner.sweep(
				declaredNamed(known, name),
				cursor === undefined ? undefined : text("cursor", cursor, cursorLength),
			),
	};
}

/** Checks every input once, the same way for every implementation: read once into plain data,
 * keys in declared spaces, and a whole batch before anything is written. */
export function checkedStore(inner: Store, declared: readonly Space[]): Store {
	const known = declaredSpaces(declared);
	const key = (value: unknown): Key => {
		const read = fields("key", value, ["space", "partition", "name"]);
		const space = spaceIn(known, read.space);
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
	/** Spaces a batch across joins declare the same guarantees, so a fault keeps or drops it whole. */
	const oneGuarantee = (keys: readonly Key[]) => {
		const sets = new Set(keys.map((k) => JSON.stringify([...new Set(k.space.guarantees)].sort())));
		if (sets.size > 1) fail("a batch across spaces joins spaces of the same guarantees only");
	};
	const batchAcross = inner.batchAcross?.bind(inner);
	const getMany = inner.getMany?.bind(inner);
	return {
		...(batchAcross
			? {
					batchAcross: async (conditions, writes, o) => {
						const checkedConditions = [...conditions].map((c) => readCondition(c, key));
						const checkedWrites = batchWrites(writes);
						const keys = [...checkedConditions, ...checkedWrites].map((x) => x.key);
						oneGuarantee(keys);
						return batchAcross(checkedConditions, checkedWrites, readBatchOptions(o, keys));
					},
				}
			: {}),
		get: async (k) => inner.get(key(k)),
		putIfAbsent: async (k, v, o) => inner.putIfAbsent(unheld(key(k)), json(v), readWriteOptions(o)),
		replaceIf: async (k, version, v, o) =>
			inner.replaceIf(unheld(key(k)), text("version", version), json(v), readWriteOptions(o)),
		removeIf: async (k, expected, o) =>
			inner.removeIf(unheld(key(k)), readExpected(expected), readLimits(o)),
		take: async (k, o) => inner.take(unheld(key(k)), readLimits(o)),
		batch: async (conditions, writes, o) => {
			const checkedConditions = [...conditions].map((c) => readCondition(c, key));
			const checkedWrites = batchWrites(writes);
			const keys = [...checkedConditions, ...checkedWrites].map((x) => x.key);
			return inner.batch(checkedConditions, checkedWrites, readBatchOptions(o, keys));
		},
		count: async (k, window, o) => inner.count(unheld(key(k)), readWindow(window), readLimits(o)),
		...(getMany ? { getMany: async (keys) => getMany([...keys].map(key)) } : {}),
		scan: async (target, cursor) =>
			inner.scan(
				spaceIn(known, target),
				cursor === undefined ? undefined : text("cursor", cursor, cursorLength),
			),
		now: () => inner.now(),
	};
}
