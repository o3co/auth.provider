import { types } from "node:util";
import { setting } from "@mod/kernel";
import { z } from "zod";

/** A value of an added claim: JSON, as the rules below take it. A null is read back alone, from a token 0.18 signed. */
export type AddedValue =
	| null
	| boolean
	| number
	| string
	| readonly AddedValue[]
	| { readonly [name: string]: AddedValue };

/**
 * The claims a grant adds to its access token, by name, as JSON values. Never one at the top that
 * an access token's issuer writes (`iss`, `sub`, `aud`, `client_id`, `scope`, `act`, `amr`, `auth_time`, `acr`, `iat`,
 * `exp`, `jti`, `cnf`, `o3co_standing_at`), nor one a specification gives a meaning the issuer never writes (`nbf`, `roles`,
 * `groups`, `entitlements`, `scp`, `may_act`, `authorization_details`, `htm`, `htu`, `ath`, `nonce`,
 * `azp`, `at_hash`, `c_hash`, `sid`, `name`, `picture`, `profile`, `email`, `email_verified`,
 * `active`, `token_type`, `username`); never `__proto__`, `constructor`, `prototype` or `toJSON` at
 * any depth.
 */
export type AddedClaims = Readonly<Record<string, AddedValue>>;

/** The names an access token's issuer writes itself. */
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
	// When the grant's own check compared the subject's boundary, for a token tied to no session.
	"o3co_standing_at",
];

/** Names a specification gives a meaning an access token's issuer does not write: no grant adds one, and a payload holding one is none the issuer wrote. */
const unwritten: ReadonlySet<string> = new Set([
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
const reserved: ReadonlySet<string> = new Set([...written, ...unwritten]);

/** Names an object's own key never takes, at any depth: the language's, and the one JSON calls. */
const objectNames = new Set(["__proto__", "constructor", "prototype", "toJSON"]);

/**
 * The limits an operator may raise, each from today's value, never below it: a token issued under
 * them is read back under them. `size` is JSON bytes in UTF-8; the lengths are code points.
 */
export const addedClaimsLimits = z
	.strictObject({
		"name-length": z
			.number()
			.int()
			.min(255)
			.max(1024)
			.prefault(255)
			.describe(
				"The longest name of an added claim, in code points, from 255 to 1024; raised only.",
			),
		"string-length": z
			.number()
			.int()
			.min(2048)
			.max(8192)
			.prefault(2048)
			.describe(
				"The longest string of an added claim, in code points, from 2048 to 8192; raised only.",
			),
		members: z
			.number()
			.int()
			.min(256)
			.max(1024)
			.prefault(256)
			.describe(
				"The most members of an object, or values of an array, in added claims, from 256 to 1024; raised only.",
			),
		values: z
			.number()
			.int()
			.min(1024)
			.max(4096)
			.prefault(1024)
			.describe("The most values in one set of added claims, from 1024 to 4096; raised only."),
		depth: z
			.number()
			.int()
			.min(8)
			.max(16)
			.prefault(8)
			.describe(
				"The deepest an added claim nests, its value at depth 1, from 8 to 16; raised only.",
			),
		size: setting
			.size("B")
			.pipe(z.number().int().min(4096).max(8192))
			.prefault("4KiB")
			.describe(
				"The largest set of added claims, as JSON in UTF-8, a size with a unit from 4KiB to 8KiB; raised only.",
			),
	})
	.prefault({});

/** The limits as read. */
export type AddedClaimsLimits = z.output<typeof addedClaimsLimits>;

const refused = (why: string) => new TypeError(`added-claims: an added claim ${why}`);
const controlOrSpace = /[\p{Cc}\p{White_Space}]/u;
/** Whether a text is at most `most` code points, its length looked at first so a long one is never walked to its end. */
const withinCodePoints = (text: string, most: number) => {
	if (text.length <= most) return true;
	if (text.length > 2 * most) return false;
	let n = 0;
	for (const _ of text) if (++n > most) return false;
	return true;
};
const bytesOf = (text: string) => Buffer.byteLength(JSON.stringify(text));

/** The walk's running counts: the values met and the bytes the JSON would take; and whether it takes a null. */
interface Walk {
	readonly limits: AddedClaimsLimits;
	nodes: number;
	bytes: number;
	readonly seen: Set<object>;
	readonly nulls: "refused" | "read";
}

/** Each count is checked as it grows, before the walk goes on. */
function node(walk: Walk) {
	const most = walk.limits.values;
	if (++walk.nodes > most) throw refused(`set holds more than ${most} values`);
}
function bytes(walk: Walk, n: number) {
	walk.bytes += n;
	const most = walk.limits.size;
	if (walk.bytes > most) throw refused(`set is over ${most} bytes as JSON`);
}

function nameOf(key: string | symbol, top: boolean, walk: Walk): string {
	if (typeof key === "symbol") throw refused("name is a symbol");
	const most = walk.limits["name-length"];
	if (key.length === 0 || !withinCodePoints(key, most)) {
		throw refused(`name is not 1 to ${most} code points`);
	}
	if (!key.isWellFormed() || controlOrSpace.test(key)) {
		throw refused("name holds a lone surrogate, a control character or a space");
	}
	if (objectNames.has(key)) throw refused("name is one an object keeps for itself");
	if (top && reserved.has(key)) throw refused("name is reserved");
	return key;
}

/**
 * The own data properties of an object or an array, read without calling anything: their number is
 * checked before any is read. Each is enumerable, but for an array's own `length`.
 */
function ownData(value: object, most: number, over: string): [string | symbol, unknown][] {
	const keys = Reflect.ownKeys(value);
	if (keys.length > most) throw refused(over);
	const array = Array.isArray(value);
	return keys.map((key) => {
		const property = Object.getOwnPropertyDescriptor(value, key);
		if (!property || !("value" in property)) throw refused("holds an accessor");
		if (!property.enumerable && !(array && key === "length")) {
			throw refused("holds a hidden property");
		}
		return [key, property.value];
	});
}

/** `at` is the value's path, as `keys` names a null: a member by `.name`, an array's value by `[i]`. */
function copy(value: unknown, depth: number, walk: Walk, at: string): AddedValue {
	if (depth > walk.limits.depth) throw refused(`is nested deeper than ${walk.limits.depth}`);
	node(walk);
	if (value === null && walk.nulls === "refused") {
		throw refused(`holds a null at ${at}: leave it out`);
	}
	if (value === null || typeof value === "boolean") {
		bytes(walk, value === null ? 4 : String(value).length);
		return value;
	}
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw refused("number is not finite");
		bytes(walk, JSON.stringify(value).length);
		return value;
	}
	if (typeof value === "string") {
		const most = walk.limits["string-length"];
		if (!withinCodePoints(value, most)) throw refused(`string is over ${most} code points`);
		if (!value.isWellFormed()) throw refused("string holds a lone surrogate");
		bytes(walk, bytesOf(value));
		return value;
	}
	if (typeof value !== "object") throw refused(`is a ${typeof value}, not JSON`);
	if (types.isProxy(value)) throw refused("is a proxy");
	if (walk.seen.has(value)) throw refused("holds itself");
	walk.seen.add(value);
	try {
		return Array.isArray(value)
			? copyArray(value, depth, walk, at)
			: copyObject(value, depth, walk, at);
	} finally {
		walk.seen.delete(value);
	}
}

function copyArray(
	value: readonly unknown[],
	depth: number,
	walk: Walk,
	path: string,
): readonly AddedValue[] {
	if (Object.getPrototypeOf(value) !== Array.prototype) throw refused("array is not a plain one");
	// A plain array's length is its own data property, read before anything else.
	const length = value.length;
	const most = walk.limits.members;
	if (length > most) throw refused(`array holds more than ${most} values`);
	// Its indexes, in order, and its length alone: a hole or a property beside them is no JSON array.
	const entries = ownData(value, length + 1, "array holds a property beside its values");
	if (entries.length !== length + 1) throw refused("array holds a hole");
	bytes(walk, 2 + Math.max(0, length - 1));
	const copied: AddedValue[] = [];
	for (let at = 0; at < length; at++) {
		const [key, entry] = entries[at] ?? [];
		if (key !== String(at)) throw refused("array holds a hole");
		copied.push(copy(entry, depth + 1, walk, `${path}[${at}]`));
	}
	return Object.freeze(copied);
}

function plainMembers(value: object, most: number, over: string): [string | symbol, unknown][] {
	const prototype = Object.getPrototypeOf(value);
	if (prototype !== Object.prototype && prototype !== null)
		throw refused("object is not a plain one");
	return ownData(value, most, over);
}

function copyObject(value: object, depth: number, walk: Walk, path: string): AddedClaims {
	const most = walk.limits.members;
	const entries = plainMembers(value, most, `object holds more than ${most} members`);
	bytes(walk, 2 + Math.max(0, entries.length - 1));
	const copied: Record<string, AddedValue> = {};
	for (const [key, member] of entries) {
		const name = nameOf(key, false, walk);
		bytes(walk, bytesOf(name) + 1);
		copied[name] = copy(member, depth + 1, walk, `${path}.${name}`);
	}
	return Object.freeze(copied);
}

/** The checks and copies of added claims under `limits`, as the operator set them. */
export function addedClaimsWith(limits: AddedClaimsLimits) {
	return {
		/**
		 * The claims a grant adds, checked and copied: a new frozen record of JSON values within the
		 * limits, every name not reserved; none for none or an empty set. Throws TypeError, the grant's
		 * maker's mistake, on anything else: nothing given is called, nor used past the copy.
		 */
		of: (given: unknown) => copied(given, "refused", limits),
		/**
		 * The added claims of a token read back, checked and copied as a grant's are but for a null.
		 * Signing took one under 0.18, so a token it signed may hold one, and is read as it was signed.
		 */
		readBack: (given: unknown) => copied(given, "read", limits),
	};
}

/** The checks under the default limits. */
const byDefault = addedClaimsWith(addedClaimsLimits.parse({}));
/** @deprecated `addedClaimsWith`'s `of` under the default limits; use `addedClaimsWith(limits).of`. */
export const addedClaimsOf = byDefault.of;
/** @deprecated `addedClaimsWith`'s `readBack` under the default limits; use `addedClaimsWith(limits).readBack`. */
export const addedClaimsReadBack = byDefault.readBack;

function copied(
	given: unknown,
	nulls: Walk["nulls"],
	limits: AddedClaimsLimits,
): AddedClaims | undefined {
	if (given === undefined) return undefined;
	if (given === null || typeof given !== "object" || Array.isArray(given)) {
		throw refused("set is not an object");
	}
	if (types.isProxy(given)) throw refused("set is a proxy");
	const entries = plainMembers(
		given,
		limits.members,
		`set holds more than ${limits.members} claims`,
	);
	if (entries.length === 0) return undefined;
	const walk: Walk = { limits, nodes: 0, bytes: 0, seen: new Set([given]), nulls };
	bytes(walk, 2 + entries.length - 1);
	const taken: Record<string, AddedValue> = {};
	for (const [key, value] of entries) {
		const name = nameOf(key, true, walk);
		bytes(walk, bytesOf(name) + 1);
		taken[name] = copy(value, 1, walk, name);
	}
	return Object.freeze(taken);
}

/** The added claims a verified payload holds: its members an access token's issuer does not write. */
export function addedClaimsIn(payload: Readonly<Record<string, unknown>>): Record<string, unknown> {
	return Object.fromEntries(Object.entries(payload).filter(([name]) => !written.includes(name)));
}
