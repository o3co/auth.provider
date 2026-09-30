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
 * The `full-pki` config surface: what boot refuses, and why each refusal is a
 * refusal rather than a default. Settings that encode a security decision are
 * optional to *wire* and not optional to *decide*: a deployment that never
 * states its revocation posture does not get one chosen for it.
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
	readonly trustedCas?: readonly string[];
	readonly fullPki?: unknown;
}

const makeBoot = (overrides: FullPkiOverrides): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			oauth: {
				...makeValidCoreConfig().oauth,
				tokenBinding: { "dispatch-policy": "intent-explicit" },
			},
			mtls: {
				enabled: true,
				source: overrides.source ?? "header",
				certHeader: "x-forwarded-client-cert",
				certHeaderDialect: "envoy",
				mode: overrides.mode ?? "full-pki",
				trustedCas: overrides.trustedCas ?? [ROOT_PEM],
				trustedProxies: ["loopback"],
				...(overrides.fullPki === undefined ? {} : { fullPki: overrides.fullPki }),
			},
		} as never,
		pathResolver: (s: string) => s,
	}) as unknown as BootstrapMap;

const boot = (overrides: FullPkiOverrides) =>
	createApp({ modules: [mtlsModule], bootstrapComponents: makeBoot(overrides) });

const FULL_PKI_DEFAULTS = {
	maxChainDepth: 6,
	signatureAlgorithms: ["ecdsaWithSHA256", "sha256WithRSAEncryption"],
	minRsaKeyBits: 2048,
};

describe("mode = full-pki — boot invariants", () => {
	it("refuses an empty trusted-cas, as the narrow mode does", async () => {
		await expect(
			boot({
				trustedCas: [],
				fullPki: {
					...FULL_PKI_DEFAULTS,
					revocation: {
						mode: "disabled",
						onUnavailable: "reject",
						allowedHosts: [],
						fetchTimeoutMs: 3000,
						cacheTtlSeconds: 3600,
						maxResponseBytes: 1_048_576,
					},
				},
			}),
		).rejects.toThrow(/trustedCas/);
	});

	it("refuses to boot without an explicit revocation decision", async () => {
		// Not stating a revocation posture must not silently become one: any
		// default would be wrong for half the deployments that never read this far.
		//
		// Matched against the *module's* message: `createMtlsMechanism` refuses
		// the same configuration as a backstop with close wording, so a looser
		// matcher would pass on the backstop alone and miss the removal of the
		// boot check, the one naming config keys the operator can act on.
		await expect(boot({ fullPki: FULL_PKI_DEFAULTS })).rejects.toThrow(
			/mtlsModule:[\s\S]*mtls\.fullPki\.revocation\.mode and \.onUnavailable/,
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
				fullPki: {
					...FULL_PKI_DEFAULTS,
					revocation: {
						mode: "crl",
						onUnavailable: "reject",
						allowedHosts: [],
						fetchTimeoutMs: 3000,
						cacheTtlSeconds: 3600,
						maxResponseBytes: 1_048_576,
					},
				},
			}),
		).rejects.toThrow(/allowedHosts/);
	});

	it.each(["ocsp", "both"] as const)(
		"refuses revocation.mode = %s with no allowed-hosts",
		async (mode) => {
			// A responder URL is a destination inside a certificate exactly as a
			// distribution point is; the same second layer applies.
			await expect(
				boot({
					fullPki: {
						...FULL_PKI_DEFAULTS,
						revocation: {
							mode,
							onUnavailable: "reject",
							allowedHosts: [],
							fetchTimeoutMs: 3000,
							cacheTtlSeconds: 3600,
							maxResponseBytes: 1_048_576,
							ocspRequireNonce: true,
						},
					},
				}),
			).rejects.toThrow(/allowedHosts/);
		},
	);

	it.each(["ocsp", "both"] as const)(
		"boots with revocation.mode = %s and an allowlist",
		async (mode) => {
			const handle = await boot({
				fullPki: {
					...FULL_PKI_DEFAULTS,
					revocation: {
						mode,
						onUnavailable: "reject",
						allowedHosts: ["ocsp.example.test"],
						fetchTimeoutMs: 3000,
						cacheTtlSeconds: 3600,
						maxResponseBytes: 1_048_576,
						ocspRequireNonce: true,
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
			fullPki: {
				...FULL_PKI_DEFAULTS,
				revocation: {
					mode: "disabled",
					onUnavailable: "reject",
					allowedHosts: [],
					fetchTimeoutMs: 3000,
					cacheTtlSeconds: 3600,
					maxResponseBytes: 1_048_576,
				},
			},
		});
		await handle.dispose();
	});

	it("boots with source = tls-layer, which the narrow mode still refuses", async () => {
		// tls-layer is the default source, so refusing it here would leave the
		// most likely PKI configuration unreachable.
		const handle = await boot({
			source: "tls-layer",
			fullPki: {
				...FULL_PKI_DEFAULTS,
				revocation: {
					mode: "crl",
					onUnavailable: "reject",
					allowedHosts: ["crl.example.test"],
					fetchTimeoutMs: 3000,
					cacheTtlSeconds: 3600,
					maxResponseBytes: 1_048_576,
				},
			},
		});
		await handle.dispose();
	});

	it("refuses tls-layer in the narrow pki mode", async () => {
		await expect(boot({ mode: "pki", source: "tls-layer" })).rejects.toThrow(/tls-layer/);
	});
});

describe("mtlsConfigSchema — full-pki", () => {
	const parse = (mtls: Record<string, unknown>) => mtlsConfigSchema.safeParse(mtls);

	it.each(["ocsp", "both"] as const)(
		"accepts revocation.mode = %s with a non-empty allowed-hosts",
		(mode) => {
			// Accepted because the code honours it; a mode it does not implement
			// is refused rather than accepted and ignored (next case).
			const result = parse({
				enabled: true,
				mode: "full-pki",
				fullPki: {
					revocation: { mode, onUnavailable: "reject", allowedHosts: ["ocsp.example.test"] },
				},
			});
			expect(result.success).toBe(true);
		},
	);

	it("still refuses a revocation mode it does not implement", () => {
		const result = parse({
			enabled: true,
			mode: "full-pki",
			fullPki: {
				revocation: { mode: "stapled", onUnavailable: "reject" },
			},
		});
		expect(result.success).toBe(false);
	});

	it("requires on-unavailable for OCSP exactly as for CRL", () => {
		const result = parse({
			enabled: true,
			mode: "full-pki",
			fullPki: {
				revocation: { mode: "ocsp", allowedHosts: ["ocsp.example.test"] },
			},
		});
		expect(result.success).toBe(false);
	});

	it("requires the nonce by default (RFC 8954), and lets an operator state otherwise", () => {
		const strict = mtlsConfigSchema.parse({
			enabled: true,
			mode: "full-pki",
			fullPki: {
				revocation: {
					mode: "ocsp",
					onUnavailable: "reject",
					allowedHosts: ["ocsp.example.test"],
				},
			},
		});
		expect(strict.fullPki?.revocation?.ocspRequireNonce).toBe(true);

		const lenient = mtlsConfigSchema.parse({
			enabled: true,
			mode: "full-pki",
			fullPki: {
				revocation: {
					mode: "ocsp",
					onUnavailable: "reject",
					allowedHosts: ["ocsp.example.test"],
					ocspRequireNonce: false,
				},
			},
		});
		expect(lenient.fullPki?.revocation?.ocspRequireNonce).toBe(false);
	});

	it("refuses an unknown signature algorithm rather than matching nothing", () => {
		// A typo that silently matched nothing would leave a deployment
		// believing it had a policy while rejecting every certificate.
		const result = parse({
			enabled: true,
			mode: "full-pki",
			fullPki: {
				signatureAlgorithms: ["sha1WithRSAEncryption"],
				revocation: { mode: "crl", onUnavailable: "reject" },
			},
		});
		expect(result.success).toBe(false);
	});

	it("has no name for SHA-1, so the allowlist cannot be widened to it", () => {
		const result = parse({
			enabled: true,
			mode: "full-pki",
			fullPki: {
				signatureAlgorithms: ["ecdsaWithSHA1"],
				revocation: { mode: "crl", onUnavailable: "reject" },
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
