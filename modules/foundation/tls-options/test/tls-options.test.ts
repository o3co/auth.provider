import { describe, expect, it } from "vitest";
import { tlsOptions } from "../src/contract.ts";
import { handshakeWith } from "../src/testing.ts";

// A client taking anything, its security level lowered, sees each peer offer what it says alone.
const anything = { minVersion: "TLSv1", ciphers: "ALL:@SECLEVEL=0" } as const;

describe("the TLS peers a client's options are held against", () => {
	it("each offers the one version and suite it says", async () => {
		expect(await handshakeWith(anything, "tls1.1")).toMatchObject({ protocol: "TLSv1.1" });
		expect(await handshakeWith(anything, "static-rsa")).toMatchObject({
			protocol: "TLSv1.2",
			cipher: "AES128-GCM-SHA256",
		});
		expect(await handshakeWith(anything, "cbc")).toMatchObject({
			protocol: "TLSv1.2",
			cipher: "ECDHE-ECDSA-AES128-SHA256",
		});
		expect(await handshakeWith(anything, "ecdhe-aead")).toMatchObject({
			protocol: "TLSv1.2",
			cipher: "ECDHE-ECDSA-AES128-GCM-SHA256",
		});
		expect(await handshakeWith(anything, "tls1.3")).toMatchObject({ protocol: "TLSv1.3" });
	});

	it("refuses a client that offers no suite the peer takes", async () => {
		expect(await handshakeWith({ minVersion: "TLSv1.3" }, "ecdhe-aead")).toEqual({
			kind: "refused",
		});
	});
});

describe("tlsOptions", () => {
	it("refuses an old TLS, the RSA key exchange and CBC, and takes ECDHE with AEAD and TLS 1.3 [oidc-core-16.17-b] [oidc-core-16.17-c] [oidc-discovery-7.1-b] [oidc-discovery-7.1-c]", async () => {
		const outcomes = Object.fromEntries(
			await Promise.all(
				(["tls1.1", "static-rsa", "cbc", "ecdhe-aead", "tls1.3"] as const).map(
					async (offer) => [offer, (await handshakeWith(tlsOptions, offer)).kind] as const,
				),
			),
		);
		expect(outcomes).toEqual({
			"tls1.1": "refused",
			"static-rsa": "refused",
			cbc: "refused",
			"ecdhe-aead": "agreed",
			"tls1.3": "agreed",
		});
	});

	it("cannot be changed in place", () => {
		expect(Object.isFrozen(tlsOptions)).toBe(true);
	});
});
