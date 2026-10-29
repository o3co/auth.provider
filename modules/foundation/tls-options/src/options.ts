import type { FloorKeys, HeldToFloor, TlsOptions } from "./contract.ts";
import type { Settings } from "./section.ts";

/**
 * The floor's own mark, as kernel marks its values: one symbol for every copy of this package, so a
 * floor another copy made is known too, and a spread or `Object.assign` copy, never carrying it, is not.
 */
const mark = Symbol.for("@mod/tls-options.floor");

/**
 * The options a read section gives, marked and frozen. TLS 1.3's suites are named in `ciphers`, which
 * Node reads for both versions; no `maxVersion`, so a later TLS is never cut. The certificate is always
 * checked, so `NODE_TLS_REJECT_UNAUTHORIZED`, which Node reads only where a connection names nothing,
 * never switches the check off.
 */
export function optionsOf(s: Settings): TlsOptions {
	const options: FloorKeys = {
		minVersion: s["min-version"],
		ciphers: s.suites.join(":"),
		rejectUnauthorized: true,
	};
	Object.defineProperty(options, mark, { value: true, enumerable: false });
	return Object.freeze(options) as unknown as TlsOptions;
}

/**
 * Each key a floor carries now, and the values it takes: the one list a floor is checked by, so a key
 * the floor gains is asked of every floor at once, one an older copy made among them.
 */
const floorKeys: { readonly [K in keyof FloorKeys]: (value: unknown) => boolean } = {
	minVersion: (value) => value === "TLSv1.2" || value === "TLSv1.3",
	ciphers: (value) => typeof value === "string" && value !== "",
	rejectUnauthorized: (value) => value === true,
};

/** Whether `value` holds `key` as a spread copies it: its own, enumerable, a value and no getter, taken by `takes`. */
const holds = (value: object, key: string, takes: (value: unknown) => boolean) => {
	const own = Object.getOwnPropertyDescriptor(value, key);
	return own !== undefined && own.enumerable === true && "value" in own && takes(own.value);
};

/** Whether `value` is a floor made here: frozen, carrying the mark as its own, of the shape made now. */
export const isMarked = (value: unknown): value is TlsOptions =>
	typeof value === "object" &&
	value !== null &&
	Object.hasOwn(value, mark) &&
	Object.isFrozen(value) &&
	Object.entries(floorKeys).every(([key, takes]) => holds(value, key, takes));

/**
 * The options `node:tls` would take over the floor's own keys: a context of its own, whose versions,
 * suites and authorities the floor's keys no longer set; a protocol method or OpenSSL flags beside
 * `minVersion`; and another check of the peer's name, or a pre-shared key, in place of its certificate.
 */
const passingTheFloor = [
	"secureContext",
	"secureProtocol",
	"secureOptions",
	"checkServerIdentity",
	"pskCallback",
] as const;

/**
 * `options`, the floor's own keys copied last over them. A value no tls-options made throws, as do
 * options carrying any key that would take the connection past the floor.
 */
export function heldTo<T extends object>(floor: TlsOptions, options: T): HeldToFloor<T> {
	if (!isMarked(floor)) {
		throw new TypeError(
			"the TLS floor is not one tls-options made: provide it from @mod/tls-options",
		);
	}
	const passing = passingTheFloor.filter((key) => Object.hasOwn(options, key));
	if (passing.length > 0) {
		throw new TypeError(
			`options held to the TLS floor take none of ${passing.join(", ")}, which would loosen it`,
		);
	}
	// Its enumerable keys alone: the mark is not one, so the result is no floor.
	return { ...options, ...floor } as unknown as HeldToFloor<T>;
}
