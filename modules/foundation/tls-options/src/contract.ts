import type { ConnectionOptions } from "node:tls";

/**
 * The floor of every TLS connection the provider makes as a client (BCP 195, RFC 9325 §4): TLS 1.2
 * or later, and on TLS 1.2 only ECDHE with an AEAD cipher, so neither the RSA key exchange nor CBC.
 * TLS 1.3's suites are named too, as Node takes TLS 1.3 only where `ciphers` names one; no
 * `maxVersion`, so a later TLS is never cut. Spread last over a connection's own options.
 */
export const tlsOptions: Readonly<Pick<ConnectionOptions, "minVersion" | "ciphers">> =
	Object.freeze({
		minVersion: "TLSv1.2",
		ciphers: [
			"TLS_AES_256_GCM_SHA384",
			"TLS_CHACHA20_POLY1305_SHA256",
			"TLS_AES_128_GCM_SHA256",
			"ECDHE-ECDSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"ECDHE-ECDSA-AES256-GCM-SHA384",
			"ECDHE-RSA-AES256-GCM-SHA384",
			"ECDHE-ECDSA-CHACHA20-POLY1305",
			"ECDHE-RSA-CHACHA20-POLY1305",
		].join(":"),
	});
