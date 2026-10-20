import { types } from "node:util";

/** A value a grant adds to its access token: JSON, as the rules below take it. */
export type AddedValue =
	| null
	| boolean
	| number
	| string
	| readonly AddedValue[]
	| { readonly [name: string]: AddedValue };

/** The claims a grant adds to its access token, by name. */
export type AddedClaims = Readonly<Record<string, AddedValue>>;

/** The names tokens writes itself. */
const written = [
	"iss",
	"sub",
	"aud",
	"client_id",
	"scope",
	"act",
	"amr",
	"auth_time",
	"acr",
	"iat",
	"exp",
	"jti",
	"cnf",
];

/** Names a specification gives a meaning tokens does not write: no grant adds one, and a token holding one is none of tokens'. */
export const unwritten: ReadonlySet<string> = new Set([
	"nbf",
	"roles",
	"groups",
	"entitlements",
	"scp",
	"may_act",
	"authorization_details",
	"htm",
	"htu",
	"ath",
	"nonce",
	"azp",
	"at_hash",
	"c_hash",
	"sid",
	"name",
	"picture",
	"profile",
	"email",
	"email_verified",
	"active",
	"token_type",
	"username",
]);

/** Every name a grant may not add at the top. */
export const reserved: ReadonlySet<string> = new Set([...written, ...unwritten]);

/** Names an object's own key never takes, at any depth. */
const objectNames = new Set(["__proto__", "constructor", "prototype"]);

export const limits = {
	nameCodePoints: 255,
	stringCodePoints: 2048,
	members: 256,
	nodes: 1024,
	depth: 8,
	bytes: 4096,
} as const;

const refused = (why: string) => new TypeError(`tokens: an added claim ${why}`);
const controlOrSpace = /[\p{Cc}\p{White_Space}]/u;
const codePoints = (text: string) => {
	let n = 0;
	for (const _ of text) n++;
	return n;
};
const bytesOf = (text: string) => Buffer.byteLength(JSON.stringify(text));

/** The walk's running counts: the values met and the bytes the JSON would take. */
interface Walk {
	nodes: number;
	bytes: number;
	readonly seen: Set<object>;
}

function count(walk: Walk, bytes: number) {
	walk.nodes++;
	walk.bytes += bytes;
	if (walk.nodes > limits.nodes) throw refused(`set holds more than ${limits.nodes} values`);
	if (walk.bytes > limits.bytes) throw refused(`set is over ${limits.bytes} bytes as JSON`);
}

function nameOf(key: string | symbol, top: boolean): string {
	if (typeof key === "symbol") throw refused("name is a symbol");
	if (key.length === 0 || codePoints(key) > limits.nameCodePoints) {
		throw refused(`name is not 1 to ${limits.nameCodePoints} code points`);
	}
	if (!key.isWellFormed() || controlOrSpace.test(key)) {
		throw refused("name holds a lone surrogate, a control character or a space");
	}
	if (objectNames.has(key)) throw refused("name is one an object keeps for itself");
	if (top && reserved.has(key)) throw refused("name is reserved");
	return key;
}

/** The own data properties of an object or an array, read without calling anything. */
function ownData(value: object): [string | symbol, unknown][] {
	return Reflect.ownKeys(value).map((key) => {
		const property = Object.getOwnPropertyDescriptor(value, key);
		if (!property || !("value" in property)) throw refused("holds an accessor");
		if (!property.enumerable && key !== "length") throw refused("holds a hidden property");
		return [key, property.value];
	});
}

function copy(value: unknown, depth: number, walk: Walk): AddedValue {
	if (depth > limits.depth) throw refused(`is nested deeper than ${limits.depth}`);
	if (value === null || typeof value === "boolean") {
		count(walk, value === null ? 4 : String(value).length);
		return value;
	}
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw refused("number is not finite");
		count(walk, JSON.stringify(value).length);
		return value;
	}
	if (typeof value === "string") {
		if (!value.isWellFormed()) throw refused("string holds a lone surrogate");
		if (codePoints(value) > limits.stringCodePoints) {
			throw refused(`string is over ${limits.stringCodePoints} code points`);
		}
		count(walk, bytesOf(value));
		return value;
	}
	if (typeof value !== "object") throw refused(`is a ${typeof value}, not JSON`);
	if (types.isProxy(value)) throw refused("is a proxy");
	if (walk.seen.has(value)) throw refused("holds itself");
	walk.seen.add(value);
	try {
		return Array.isArray(value) ? copyArray(value, depth, walk) : copyObject(value, depth, walk);
	} finally {
		walk.seen.delete(value);
	}
}

function copyArray(value: readonly unknown[], depth: number, walk: Walk): readonly AddedValue[] {
	if (Object.getPrototypeOf(value) !== Array.prototype) throw refused("array is not a plain one");
	const entries = ownData(value);
	const length = value.length;
	if (length > limits.members) throw refused(`array holds more than ${limits.members} values`);
	// Its indexes and its length alone: a hole or a property beside them is no JSON array.
	if (entries.length !== length + 1) throw refused("array holds a hole or a property");
	count(walk, 2 + Math.max(0, length - 1));
	const copied: AddedValue[] = [];
	for (let at = 0; at < length; at++) {
		const entry = entries.find(([key]) => key === String(at));
		if (!entry) throw refused("array holds a hole");
		copied.push(copy(entry[1], depth + 1, walk));
	}
	return Object.freeze(copied);
}

function copyObject(value: object, depth: number, walk: Walk): AddedClaims {
	const prototype = Object.getPrototypeOf(value);
	if (prototype !== Object.prototype && prototype !== null) {
		throw refused("object is not a plain one");
	}
	const entries = ownData(value);
	if (entries.length > limits.members) {
		throw refused(`object holds more than ${limits.members} members`);
	}
	count(walk, 2 + Math.max(0, entries.length - 1));
	const copied: Record<string, AddedValue> = {};
	for (const [key, member] of entries) {
		const name = nameOf(key, false);
		walk.bytes += bytesOf(name) + 1;
		copied[name] = copy(member, depth + 1, walk);
	}
	return Object.freeze(copied);
}

/**
 * The claims a grant adds, checked and copied: a new frozen record of JSON values within the
 * limits, every name not reserved; none for none or an empty set. Throws TypeError, the grant's
 * maker's mistake, on anything else: nothing given is called, nor used past the copy.
 */
export function addedClaimsOf(given: unknown): AddedClaims | undefined {
	if (given === undefined) return undefined;
	if (given === null || typeof given !== "object" || Array.isArray(given)) {
		throw refused("set is not an object");
	}
	if (types.isProxy(given)) throw refused("set is a proxy");
	const prototype = Object.getPrototypeOf(given);
	if (prototype !== Object.prototype && prototype !== null) {
		throw refused("set is not a plain object");
	}
	const walk: Walk = { nodes: 0, bytes: 2, seen: new Set([given]) };
	const entries = ownData(given);
	if (entries.length === 0) return undefined;
	if (entries.length > limits.members)
		throw refused(`set holds more than ${limits.members} claims`);
	walk.bytes += entries.length - 1;
	const copied: Record<string, AddedValue> = {};
	for (const [key, value] of entries) {
		const name = nameOf(key, true);
		walk.bytes += bytesOf(name) + 1;
		copied[name] = copy(value, 1, walk);
	}
	return Object.freeze(copied);
}

/** The added claims a verified payload holds: its members tokens does not write. */
export function addedClaimsIn(payload: Readonly<Record<string, unknown>>): Record<string, unknown> {
	return Object.fromEntries(Object.entries(payload).filter(([name]) => !written.includes(name)));
}
