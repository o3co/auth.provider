import { contract } from "@mod/kernel";
import type { Settings } from "./section.ts";

export type { Settings } from "./section.ts";

/** Brands the options as made here, from a section: no other package can build one. */
declare const madeFromSection: unique symbol;

/** What a TLS connection takes, as `node:tls` takes it, made only by `optionsOf`. */
export interface TlsOptions {
	readonly minVersion: "TLSv1.2" | "TLSv1.3";
	readonly ciphers: string;
	readonly [madeFromSection]: true;
}

/**
 * The floor of every TLS connection the provider makes as a client, as the section sets it, frozen.
 * A caller copies its keys last over its own options, so nothing the caller passes loosens it.
 */
export const tlsOptions = contract<TlsOptions>("tls-options");

/**
 * The options a section gives. TLS 1.3's suites are named in `ciphers`, which Node reads for both
 * versions; no `maxVersion`, so a later TLS is never cut.
 */
export const optionsOf = (s: Settings): TlsOptions =>
	Object.freeze({ minVersion: s["min-version"], ciphers: s.suites.join(":") }) as TlsOptions;
