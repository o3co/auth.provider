import type { TlsOptions } from "./contract.ts";
import type { Settings } from "./section.ts";

/**
 * The floor's own mark, as kernel marks its values: one symbol for every copy of this package, so a
 * floor another copy made is known too, and a spread or `Object.assign` copy, never carrying it, is not.
 */
const mark = Symbol.for("@mod/tls-options.floor");

/**
 * The options a read section gives, marked and frozen. TLS 1.3's suites are named in `ciphers`, which
 * Node reads for both versions; no `maxVersion`, so a later TLS is never cut.
 */
export function optionsOf(s: Settings): TlsOptions {
	const options = { minVersion: s["min-version"], ciphers: s.suites.join(":") };
	Object.defineProperty(options, mark, { value: true, enumerable: false });
	return Object.freeze(options) as TlsOptions;
}

/** Whether `value` is a floor made here: frozen, carrying the mark as its own. */
export const isMarked = (value: unknown): value is TlsOptions =>
	typeof value === "object" &&
	value !== null &&
	Object.hasOwn(value, mark) &&
	Object.isFrozen(value);
