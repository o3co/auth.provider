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
 * WebAuthn deployer configuration schema.
 *
 * Parsed by `webauthnConfigSchema` and supplied to `webauthnModule` via the
 * bootstrap module's `provides: { webauthnConfig }` ComponentMap slot
 * (spec §2.4.1 — this package exports the schema; auth-provider-core does
 * NOT auto-intersect it into AppConfigSchema).
 *
 * Schema design principle: pure type contract (ADR 2026-04-30).
 * No `.default()` calls — all runtime defaults live exclusively in
 * `packages/webauthn/config/reference.conf` (HOCON). The ADR rule is
 * project-wide (see `tokenExchangeConfigSchema` in oauth-token-exchange
 * for the nearest analogous module-local schema). Schema parse rejects
 * bare inputs without all required fields; tests supply every field
 * explicitly rather than relying on hidden schema-side defaults.
 *
 * S11 baseline (dogfood-friendly):
 *   attestationPreference = "none"   — no attestation chain verification required;
 *                                       deployments needing device attestation
 *                                       override to "direct" + supply trust anchors.
 *   challengeTtlMs = 120_000         — 120 s; chosen as the mobile-network safe
 *                                       baseline (per spec §2.4.1 / FCoT CA4).
 *   userVerification = "preferred"   — balance between broad platform coverage
 *                                       and security posture.
 */
// biome-ignore lint/correctness/noUnusedImports: ComponentMap is used in the `declare module` augmentation below; biome does not track cross-module-declaration references.
import type { ComponentMap as _ComponentMap } from "@o3co/auth-provider-core";
import { z } from "zod";

export const webauthnConfigSchema = z.object({
	/** Relying Party ID — the effective domain, e.g. "example.com". */
	rpId: z.string().min(1),
	/** Human-readable Relying Party name shown to the user during ceremony. */
	rpName: z.string().min(1),
	/**
	 * Allowed HTTPS origin(s) for registration / authentication ceremonies.
	 * At least one entry required. Multiple entries support sub-domain or
	 * multi-app deployments sharing a single RP ID.
	 *
	 * Each origin MUST be a literal origin (scheme + host + optional port) —
	 * `https://example.com`, `https://app.example.com`, `http://localhost:3000`.
	 * Wildcards are NOT allowed: SimpleWebAuthn does exact-string-match against
	 * the authenticator's clientDataJSON, so `https://*.example.com` accepts at
	 * parse time but breaks every ceremony at runtime. Non-https schemes other
	 * than `http://localhost` are rejected because passkeys are not transmittable
	 * over insecure schemes (W3C WebAuthn §5.1.3 + browser policy).
	 *
	 * Cross-refs: Wave 1 post-merge audit M-1.
	 */
	origin: z
		.array(
			z
				.string()
				.url()
				.refine((u) => !u.includes("*"), {
					message: "origin must not contain wildcards — SimpleWebAuthn does exact-match only",
				})
				.refine(
					(u) =>
						u.startsWith("https://") ||
						u === "http://localhost" ||
						u.startsWith("http://localhost:") ||
						u.startsWith("http://127.0.0.1") ||
						u.startsWith("http://[::1]"),
					{
						message:
							"origin must be https:// or http://localhost / http://127.0.0.1 / http://[::1] (W3C WebAuthn secure-origin policy)",
					},
				),
		)
		.min(1),
	/**
	 * Challenge time-to-live in milliseconds.
	 * Reference default (S11): 120_000 ms — mobile-network safe baseline.
	 * Supplied via reference.conf per ADR 2026-04-30.
	 */
	challengeTtlMs: z.number().int().positive(),
	/**
	 * WebAuthn AttestationConveyancePreference (W3C WebAuthn §5.4.7).
	 * Reference default (S11): "none" — dogfood-friendly; no attestation
	 * chain verification required. Supplied via reference.conf.
	 */
	attestationPreference: z.enum(["none", "indirect", "direct", "enterprise"]),
	/**
	 * WebAuthn UserVerificationRequirement (W3C WebAuthn §5.8.6).
	 * Reference default (S11): "preferred". Supplied via reference.conf.
	 */
	userVerification: z.enum(["required", "preferred", "discouraged"]),
});

export type WebAuthnConfig = z.infer<typeof webauthnConfigSchema>;

// ComponentMap slot declaration-merge: exposes webauthnConfig as a typed DI
// slot. Consumers supply this via a small bootstrap module that reads from
// app config (per A5 §10.2 const-Module pattern). Uses the package-name path
// (not a relative import) consistent with the T21-established pattern for
// cross-package ComponentMap augmentation.
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly webauthnConfig?: WebAuthnConfig;
	}
}
