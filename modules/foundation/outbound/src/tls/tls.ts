import type { TlsOptions } from "@mod/tls-options";

/**
 * How each TLS connection is made: the floor it holds to (`tls-options`), spread last, and the
 * authorities a destination's certificate is checked against, for a test (the platform's otherwise).
 */
export interface Tls {
	readonly floor: TlsOptions;
	readonly ca?: string;
}

/** A connection's TLS options: the test's authorities, then the floor, so nothing loosens it. */
export const tlsOf = (tls: Tls) => ({
	...(tls.ca === undefined ? {} : { ca: tls.ca }),
	...tls.floor,
});
