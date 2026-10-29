import type { HeldToFloor, TlsOptions } from "./contract.ts";
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
	const options = {
		minVersion: s["min-version"],
		ciphers: s.suites.join(":"),
		rejectUnauthorized: true,
	};
	Object.defineProperty(options, mark, { value: true, enumerable: false });
	return Object.freeze(options) as unknown as TlsOptions;
}

/** Whether `value` is a floor made here: frozen, carrying the mark as its own, of the shape made now. */
export const isMarked = (value: unknown): value is TlsOptions =>
	typeof value === "object" &&
	value !== null &&
	Object.hasOwn(value, mark) &&
	Object.isFrozen(value) &&
	// Of the shape made now: a floor an older copy made, without the certificate check, is none.
	(value as { readonly rejectUnauthorized?: unknown }).rejectUnauthorized === true;

/** `options`, the floor's own keys copied last over them; a value no tls-options made throws. */
export function heldTo<T extends object>(floor: TlsOptions, options: T): HeldToFloor<T> {
	if (!isMarked(floor)) {
		throw new TypeError(
			"the TLS floor is not one tls-options made: provide it from @mod/tls-options",
		);
	}
	// Its enumerable keys alone: the mark is not one, so the result is no floor.
	return { ...options, ...floor } as unknown as HeldToFloor<T>;
}
