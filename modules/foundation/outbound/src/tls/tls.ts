import type { TlsOptions } from "@mod/tls-options";

/**
 * How each TLS connection is made: the floor it holds to (`tls-options`), and the authorities a
 * destination's certificate is checked against, for a test (the platform's otherwise).
 */
export interface Tls {
	readonly floor?: TlsOptions;
	readonly ca?: string;
}

/**
 * A connection's TLS options: the test's authorities, then the floor's own keys alone, so nothing
 * loosens it and nothing else rides in with it.
 */
export const tlsOf = (tls: Tls) => {
	const { floor } = tls;
	return {
		...(tls.ca === undefined ? {} : { ca: tls.ca }),
		...(floor === undefined ? {} : { minVersion: floor.minVersion, ciphers: floor.ciphers }),
	};
};
