import { z } from "zod";
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
export declare const mtlsConfigSchema: z.ZodObject<{
    oauth: z.ZodObject<{
        mtls: z.ZodDefault<z.ZodObject<{
            enabled: z.ZodDefault<z.ZodBoolean>;
            source: z.ZodDefault<z.ZodEnum<{
                header: "header";
                "tls-layer": "tls-layer";
            }>>;
            "cert-header": z.ZodDefault<z.ZodString>;
            "cert-header-dialect": z.ZodDefault<z.ZodEnum<{
                envoy: "envoy";
                "plain-pem": "plain-pem";
            }>>;
            mode: z.ZodDefault<z.ZodEnum<{
                "self-signed": "self-signed";
                pki: "pki";
            }>>;
            "trusted-cas": z.ZodDefault<z.ZodReadonly<z.ZodArray<z.ZodString>>>;
        }, z.core.$strip>>;
    }, z.core.$strip>;
}, z.core.$strip>;
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
export declare const mtlsModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=module.d.mts.map