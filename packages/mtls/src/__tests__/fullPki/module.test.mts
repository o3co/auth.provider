/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The `full-pki` config surface (#341) — what boot refuses, and why each
 * refusal is a refusal rather than a default.
 *
 * The theme is #363's absence policy applied to configuration: the settings
 * that encode a security decision are optional to *wire* and not optional to
 * *decide*. A deployment that never states its revocation posture does not
 * get one chosen for it.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { type BootstrapMap, createApp } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { mtlsConfigSchema, mtlsModule } from "#/module.mjs";

const fixturesDir = join(dirname(dirname(fileURLToPath(import.meta.url))), "fixtures");
const ROOT_PEM = readFileSync(join(fixturesDir, "root.pem"), "utf8");

interface FullPkiOverrides {
	readonly source?: "header" | "tls-layer";
	readonly mode?: "self-signed" | "pki" | "full-pki";
	readonly "trusted-cas"?: readonly string[];
	readonly "full-pki"?: unknown;
}

const makeBoot = (overrides: FullPkiOverrides): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			oauth: {
				...makeValidCoreConfig().oauth,
				mtls: {
					enabled: true,
					source: overrides.source ?? "header",
					"cert-header": "x-forwarded-client-cert",
					"cert-header-dialect": "envoy",
					mode: overrides.mode ?? "full-pki",
					"trusted-cas": overrides["trusted-cas"] ?? [ROOT_PEM],
					"trusted-proxies": ["loopback"],
					...(overrides["full-pki"] === undefined ? {} : { "full-pki": overrides["full-pki"] }),
				},
				tokenBinding: { "dispatch-policy": "intent-explicit" },
			},
		} as never,
		pathResolver: (s: string) => s,
	}) as unknown as BootstrapMap;

const boot = (overrides: FullPkiOverrides) =>
	createApp({ modules: [mtlsModule], bootstrapComponents: makeBoot(overrides) });

const FULL_PKI_DEFAULTS = {
	"max-chain-depth": 6,
	"signature-algorithms": ["ecdsaWithSHA256", "sha256WithRSAEncryption"],
	"min-rsa-key-bits": 2048,
};

describe("mode = full-pki — boot invariants (#341)", () => {
	it("refuses an empty trusted-cas, as the narrow mode does", async () => {
		await expect(
			boot({
				"trusted-cas": [],
				"full-pki": {
					...FULL_PKI_DEFAULTS,
					revocation: {
						mode: "disabled",
						"on-unavailable": "reject",
						"allowed-hosts": [],
						"fetch-timeout-ms": 3000,
						"cache-ttl-seconds": 3600,
						"max-response-bytes": 1_048_576,
					},
				},
			}),
		).rejects.toThrow(/trusted-cas/);
	});

	it("refuses to boot without an explicit revocation decision", async () => {
		// The whole point: not stating a revocation posture must not silently
		// become one. Whichever default were chosen, half of the deployments
		// that never read this far would get the wrong one, and would find out
		// during an outage or after a compromise.
		//
		// Asserted against the *module's* message specifically. `createMtlsMechanism`
		// refuses the same configuration as a backstop, with wording close
		// enough that a looser matcher would pass on the backstop alone and stop
		// noticing if the boot check were removed — which is the check that
		// produces an error naming config keys the operator can act on.
		await expect(boot({ "full-pki": FULL_PKI_DEFAULTS })).rejects.toThrow(
			/mtlsModule:[\s\S]*oauth\.mtls\.full-pki\.revocation\.mode and \.on-unavailable/,
		);
	});

	it("refuses the same configuration at the mechanism factory, as a backstop", async () => {
		// A composition root that builds the mechanism directly bypasses the
		// module manifest and its boot checks. Defaulting there would reopen the
		// hole the module closes, so it refuses too.
		const { createMtlsMechanism } = await import("#/extractor.mjs");
		expect(() =>
			createMtlsMechanism({
				source: "header",
				certHeader: "x-forwarded-client-cert",
				certHeaderDialect: "envoy",
				trustedProxies: ["loopback"],
				mode: "full-pki",
				trustedCas: [ROOT_PEM],
				fullPki: {
					"max-chain-depth": 6,
					"signature-algorithms": ["ecdsaWithSHA256"],
					"min-rsa-key-bits": 2048,
				},
			}),
		).toThrow(/createMtlsMechanism:[\s\S]*no default/);
	});

	it("refuses revocation.mode = crl with no allowed-hosts", async () => {
		await expect(
			boot({
				"full-pki": {
					...FULL_PKI_DEFAULTS,
					revocation: {
						mode: "crl",
						"on-unavailable": "reject",
						"allowed-hosts": [],
						"fetch-timeout-ms": 3000,
						"cache-ttl-seconds": 3600,
						"max-response-bytes": 1_048_576,
					},
				},
			}),
		).rejects.toThrow(/allowed-hosts/);
	});

	it.each(["ocsp", "both"] as const)(
		"refuses revocation.mode = %s with no allowed-hosts (#431)",
		async (mode) => {
			// A responder URL is a destination inside a certificate exactly as a
			// distribution point is; the same second layer applies.
			await expect(
				boot({
					"full-pki": {
						...FULL_PKI_DEFAULTS,
						revocation: {
							mode,
							"on-unavailable": "reject",
							"allowed-hosts": [],
							"fetch-timeout-ms": 3000,
							"cache-ttl-seconds": 3600,
							"max-response-bytes": 1_048_576,
							"ocsp-require-nonce": true,
						},
					},
				}),
			).rejects.toThrow(/allowed-hosts/);
		},
	);

	it.each(["ocsp", "both"] as const)(
		"boots with revocation.mode = %s and an allowlist (#431)",
		async (mode) => {
			const handle = await boot({
				"full-pki": {
					...FULL_PKI_DEFAULTS,
					revocation: {
						mode,
						"on-unavailable": "reject",
						"allowed-hosts": ["ocsp.example.test"],
						"fetch-timeout-ms": 3000,
						"cache-ttl-seconds": 3600,
						"max-response-bytes": 1_048_576,
						"ocsp-require-nonce": true,
					},
				},
			});
			await handle.dispose();
		},
	);

	it("boots when revocation is explicitly disabled", async () => {
		// "disabled" is a statement, not an omission — and it is accepted,
		// because an operator who has written it down has made the decision.
		const handle = await boot({
			"full-pki": {
				...FULL_PKI_DEFAULTS,
				revocation: {
					mode: "disabled",
					"on-unavailable": "reject",
					"allowed-hosts": [],
					"fetch-timeout-ms": 3000,
					"cache-ttl-seconds": 3600,
					"max-response-bytes": 1_048_576,
				},
			},
		});
		await handle.dispose();
	});

	it("boots with source = tls-layer, which the narrow mode still refuses", async () => {
		// #341's "Related: TLS-layer chains". #280 made tls-layer the default
		// source, which left the most likely PKI configuration unreachable.
		const handle = await boot({
			source: "tls-layer",
			"full-pki": {
				...FULL_PKI_DEFAULTS,
				revocation: {
					mode: "crl",
					"on-unavailable": "reject",
					"allowed-hosts": ["crl.example.test"],
					"fetch-timeout-ms": 3000,
					"cache-ttl-seconds": 3600,
					"max-response-bytes": 1_048_576,
				},
			},
		});
		await handle.dispose();
	});

	it("leaves the narrow mode's tls-layer refusal exactly as it was", async () => {
		await expect(boot({ mode: "pki", source: "tls-layer" })).rejects.toThrow(/tls-layer/);
	});
});

describe("mtlsConfigSchema — full-pki (#341)", () => {
	const parse = (mtls: Record<string, unknown>) => mtlsConfigSchema.safeParse({ oauth: { mtls } });

	it.each(["ocsp", "both"] as const)(
		"accepts revocation.mode = %s now that OCSP is implemented (#431)",
		(mode) => {
			// Until #431 this value was refused rather than accepted and ignored —
			// the #283/#284 posture. Accepting it now is the same posture: the
			// code honours the claim.
			const result = parse({
				enabled: true,
				mode: "full-pki",
				"full-pki": {
					revocation: { mode, "on-unavailable": "reject", "allowed-hosts": ["ocsp.example.test"] },
				},
			});
			expect(result.success).toBe(true);
		},
	);

	it("still refuses a revocation mode it does not implement", () => {
		const result = parse({
			enabled: true,
			mode: "full-pki",
			"full-pki": {
				revocation: { mode: "stapled", "on-unavailable": "reject" },
			},
		});
		expect(result.success).toBe(false);
	});

	it("requires on-unavailable for OCSP exactly as for CRL", () => {
		const result = parse({
			enabled: true,
			mode: "full-pki",
			"full-pki": {
				revocation: { mode: "ocsp", "allowed-hosts": ["ocsp.example.test"] },
			},
		});
		expect(result.success).toBe(false);
	});

	it("requires the nonce by default (RFC 8954), and lets an operator state otherwise", () => {
		const strict = mtlsConfigSchema.parse({
			oauth: {
				mtls: {
					enabled: true,
					mode: "full-pki",
					"full-pki": {
						revocation: {
							mode: "ocsp",
							"on-unavailable": "reject",
							"allowed-hosts": ["ocsp.example.test"],
						},
					},
				},
			},
		});
		expect(strict.oauth.mtls["full-pki"]?.revocation?.["ocsp-require-nonce"]).toBe(true);

		const lenient = mtlsConfigSchema.parse({
			oauth: {
				mtls: {
					enabled: true,
					mode: "full-pki",
					"full-pki": {
						revocation: {
							mode: "ocsp",
							"on-unavailable": "reject",
							"allowed-hosts": ["ocsp.example.test"],
							"ocsp-require-nonce": false,
						},
					},
				},
			},
		});
		expect(lenient.oauth.mtls["full-pki"]?.revocation?.["ocsp-require-nonce"]).toBe(false);
	});

	it("refuses an unknown signature algorithm rather than matching nothing", () => {
		// A typo that silently matched nothing would leave a deployment
		// believing it had a policy while rejecting every certificate.
		const result = parse({
			enabled: true,
			mode: "full-pki",
			"full-pki": {
				"signature-algorithms": ["sha1WithRSAEncryption"],
				revocation: { mode: "crl", "on-unavailable": "reject" },
			},
		});
		expect(result.success).toBe(false);
	});

	it("has no name for SHA-1, so the allowlist cannot be widened to it", () => {
		const result = parse({
			enabled: true,
			mode: "full-pki",
			"full-pki": {
				"signature-algorithms": ["ecdsaWithSHA1"],
				revocation: { mode: "crl", "on-unavailable": "reject" },
			},
		});
		expect(result.success).toBe(false);
	});

	it("still accepts a config that never mentions full-pki", () => {
		// The block is optional; only selecting the mode makes it required.
		const result = parse({ enabled: false });
		expect(result.success).toBe(true);
	});
});
