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
 * mTLS module manifest — wires `createMtlsMechanism` into the grant
 * middleware contribution slot (Wave 2 Token-binding Cluster spec §4.7 /
 * Phase 3 spec §11.1).
 *
 * Contributions:
 *   - `grantMiddleware[0]` — `tokenBindingMw` wrapping the mTLS mechanism.
 *     Returns `null` (skip) when `config.oauth.mtls.enabled === false`.
 *
 * DI requires: `config` (reads `config.oauth.mtls` + `config.oauth.tokenBinding`).
 * DI optional: `logger` (forwarded to `tokenBindingMw` + `createMtlsMechanism`).
 *
 * No `ComponentMap` augmentation is needed for mTLS — unlike DPoP, the
 * mechanism has no consumer-wired dependencies (no replay store).
 *
 * Secure-default-opt-in: `oauth.mtls.enabled = false` in reference.conf.
 * Operators must explicitly set `enabled = true` to activate mTLS.
 *
 * Per Wave 2 Phase 3 spec §10 (config) + §11 (module) + feedback_secure_default_opt_in.md.
 */
import { defineModule } from "@o3co/auth-provider-core";
import { z } from "zod";
import { createMtlsMechanism } from "./extractor.mjs";
// ---------------------------------------------------------------------------
// Config schema
// ---------------------------------------------------------------------------
/**
 * Zod schema for the `oauth.mtls` config slice.
 *
 * Keys use kebab-case to match the HOCON reference.conf keys verbatim.
 * HOCON preserves key names exactly; TypeScript accesses them via bracket
 * notation: `config.oauth.mtls["cert-header"]`.
 *
 * NOTE: `oauth.tokenBinding.dispatch-policy` is declared by core's bundled
 * `CoreConfigSchema` since the cross-mechanism dispatch refactor — it
 * applies across ALL installed binding-mechanism modules (DPoP, mTLS, ...).
 * This package no longer redeclares it.
 *
 * Per Wave 2 Phase 3 spec §10.2.
 */
export const mtlsConfigSchema = z.object({
    oauth: z.object({
        mtls: z
            .object({
            /** When false (default), mtlsModule contributes null — no mTLS middleware mounted. */
            enabled: z.boolean().default(false),
            /** Where the leaf cert comes from. */
            source: z.enum(["header", "tls-layer"]).default("header"),
            /** Header name carrying the forwarded leaf cert (header source only). */
            "cert-header": z.string().min(1).default("x-forwarded-client-cert"),
            /** Dialect for the forwarded-cert header (header source only). */
            "cert-header-dialect": z.enum(["envoy", "plain-pem"]).default("envoy"),
            /** Trust posture: "self-signed" accepts any well-formed cert; "pki" requires trusted-cas. */
            mode: z.enum(["self-signed", "pki"]).default("self-signed"),
            /** Trust anchors for mode = "pki". Each entry: literal PEM or "file:<path>". */
            "trusted-cas": z.array(z.string()).readonly().default([]),
        })
            .default(() => ({
            enabled: false,
            source: "header",
            "cert-header": "x-forwarded-client-cert",
            "cert-header-dialect": "envoy",
            mode: "self-signed",
            "trusted-cas": [],
        })),
    }),
});
// ---------------------------------------------------------------------------
// Module manifest
// ---------------------------------------------------------------------------
/**
 * Declarative manifest for the mTLS package.
 *
 * When `config.oauth.mtls.enabled` is `false` (the secure default), the
 * mechanism factory returns `null` and core's synthesizer filters it out —
 * no mTLS mechanism is included in the composed `tokenBindingMw`. When
 * `enabled` is `true`, the factory returns the configured mTLS mechanism
 * for core to compose alongside any other binding-mechanism modules
 * (DPoP, future) under the unified `oauth.tokenBinding.dispatch-policy`.
 *
 * Boot-time fail-loud invariants (Phase 3 spec §11.2):
 *
 *   1. `mode === "pki"` + empty `trusted-cas` → throw. Without trusted CAs,
 *      chain validation cannot proceed. Failing boot directs the operator
 *      straight to the misconfig instead of either silently failing open
 *      (no validation) or failing closed on every request (no audit signal).
 *
 *   2. `mode === "pki"` + `source === "tls-layer"` → throw (Codex Round 1
 *      Important #1 fix). The narrow PKI mode requires the intermediate
 *      chain (XFCC `Chain=` parameter); TLS-layer full-chain extraction is
 *      deferred to a future phase (§1.3). Rejecting at boot avoids the same
 *      silent-fail ambiguity.
 *
 * `createMtlsMechanism` re-enforces both invariants defensively, but the
 * module fires first and produces operator-friendly error messages.
 *
 * Migrated from the `grantMiddleware` contribution slot (Phase 3 Sub-PR 3b)
 * to `tokenBindingMechanisms` (cross-mechanism dispatch refactor, 2026-05-19)
 * so the `DispatchPolicy` can arbitrate cross-module when both DPoP and
 * mTLS are installed.
 *
 * See ADR `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`
 * for the cross-mechanism design rationale.
 */
export const mtlsModule = defineModule({
    name: "mtls",
    configSchema: mtlsConfigSchema,
    requires: ["config"],
    optional: ["logger"],
    contributes: {
        tokenBindingMechanisms: [
            (deps) => {
                const mtlsConfig = deps.config.oauth
                    ?.mtls;
                if (!mtlsConfig || mtlsConfig.enabled !== true) {
                    // Disabled by config — no mechanism contributed.
                    return null;
                }
                const typedConfig = deps.config;
                const cfg = typedConfig.oauth.mtls;
                // --- Boot-time fail-loud check 1: PKI mode requires trusted-cas. ---
                if (cfg.mode === "pki" && cfg["trusted-cas"].length === 0) {
                    throw new Error('mtlsModule: config.oauth.mtls.mode = "pki" requires a non-empty oauth.mtls.trusted-cas. ' +
                        "Without trusted CAs, chain validation cannot proceed.");
                }
                // --- Boot-time fail-loud check 2: PKI + tls-layer is not supported. ---
                if (cfg.mode === "pki" && cfg.source === "tls-layer") {
                    throw new Error('mtlsModule: config.oauth.mtls.mode = "pki" with source = "tls-layer" is not supported in Phase 3. ' +
                        "The narrow PKI mode requires the intermediate chain (e.g., the Envoy XFCC " +
                        "Chain= parameter); TLS-layer full-chain extraction is deferred to a future " +
                        'phase. Use source = "header" with cert-header-dialect = "envoy" for PKI mode, ' +
                        'or use mode = "self-signed" with TLS-layer source.');
                }
                return createMtlsMechanism({
                    source: cfg.source,
                    certHeader: cfg["cert-header"],
                    certHeaderDialect: cfg["cert-header-dialect"],
                    mode: cfg.mode,
                    trustedCas: cfg["trusted-cas"],
                    logger: deps.logger,
                });
            },
        ],
    },
});
