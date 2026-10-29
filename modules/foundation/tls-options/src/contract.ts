import { contract } from "@mod/kernel";
import { heldTo, isMarked } from "./options.ts";

export type { Settings } from "./section.ts";

/** Brands the options as made here, from a section: no other package can write one. */
declare const madeFromSection: unique symbol;

/** The floor's own keys, as `node:tls` takes them; which keys they are is tls-options' alone. */
export interface FloorKeys {
	readonly minVersion: "TLSv1.2" | "TLSv1.3";
	readonly ciphers: string;
	readonly rejectUnauthorized: true;
}

/** What a TLS connection takes, as `node:tls` takes it, made only by tls-options from its section. */
export interface TlsOptions {
	readonly minVersion: "TLSv1.2" | "TLSv1.3";
	readonly ciphers: string;
	readonly [madeFromSection]: true;
}

/** A caller's options held to the floor: its own keys, but where the floor's replace them. */
export type HeldToFloor<T> = Omit<T, keyof FloorKeys> & FloorKeys;

/**
 * The floor of every TLS connection the provider makes as a client, as the section sets it, frozen.
 * A caller checks it with `isFloor`, then copies its keys last over its own options, so nothing
 * the caller passes loosens it.
 */
export const tlsOptions = contract<TlsOptions>("tls-options");

/**
 * Whether `value` is a floor tls-options made, by any copy of the package: frozen, carrying its mark.
 * A copy (a spread, `Object.assign`), a cast or a frozen value written elsewhere is not, however its
 * type reads, and is to be refused.
 */
export const isFloor: (value: unknown) => value is TlsOptions = isMarked;

/**
 * The caller's `options` with the floor's own keys copied last over them, so nothing the caller passes
 * loosens it, whatever keys the floor comes to hold. It throws a TypeError for a value `isFloor`
 * refuses: a caller checks the floor at boot, and this holds the line again at each use.
 */
export const heldToFloor: <T extends object>(floor: TlsOptions, options: T) => HeldToFloor<T> =
	heldTo;
