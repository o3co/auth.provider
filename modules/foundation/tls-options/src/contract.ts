import type { ConnectionOptions } from "node:tls";
import { contract } from "@mod/kernel";
import type { Settings } from "./section.ts";

/** What a TLS connection takes, as `node:tls` takes it. */
export type TlsOptions = Readonly<Pick<ConnectionOptions, "minVersion" | "ciphers">>;

/**
 * The floor of every TLS connection the provider makes as a client, as the section sets it, frozen.
 * Spread last over a connection's own options, so nothing the caller passes loosens it.
 */
export const tlsOptions = contract<TlsOptions>("tls-options");

/**
 * The options a section gives. Node takes TLS 1.3 only where `ciphers` names one of its suites, so
 * they are named among the rest; no `maxVersion`, so a later TLS is never cut.
 */
export const optionsOf = (s: Settings): TlsOptions =>
	Object.freeze({ minVersion: s["min-version"], ciphers: s.suites.join(":") });
