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
     * MUST NOT include a trailing slash (`https://example.com/` will never match
     * the browser-sent clientDataJSON origin, which is the literal-origin form).
     * Wildcards are NOT allowed: SimpleWebAuthn does exact-string-match against
     * the authenticator's clientDataJSON, so `https://*.example.com` accepts at
     * parse time but breaks every ceremony at runtime. Non-https schemes other
     * than `http://localhost` are rejected because passkeys are not transmittable
     * over insecure schemes (W3C WebAuthn §5.1.3 + browser policy).
     *
     * Cross-refs: Wave 1 post-merge audit M-1.
     */
    origin: z
        .array(z
        .string()
        .url()
        .refine((u) => !u.includes("*"), {
        message: "origin must not contain wildcards — SimpleWebAuthn does exact-match only",
    })
        .refine((u) => {
        // URL-parse-based check (not string-prefix) so attacker-prefix
        // bypasses like `http://127.0.0.1.evil.com`, `http://127.0.0.1@evil.com`,
        // `http://[::1]@evil.com` are rejected. The .url() validator above
        // guarantees parseability.
        let parsed;
        try {
            parsed = new URL(u);
        }
        catch {
            return false;
        }
        // Reject userinfo (`user@host`) regardless of scheme — origins must
        // not carry credentials.
        if (parsed.username !== "" || parsed.password !== "")
            return false;
        if (parsed.protocol === "https:")
            return true;
        if (parsed.protocol === "http:") {
            // W3C WebAuthn / browser secure-context policy allows http only
            // for loopback. Hostname comparison is exact-match.
            return (parsed.hostname === "localhost" ||
                parsed.hostname === "127.0.0.1" ||
                parsed.hostname === "[::1]");
        }
        return false;
    }, {
        message: "origin must be https:// or http:// loopback (localhost / 127.0.0.1 / [::1]) with no userinfo (W3C WebAuthn secure-origin policy)",
    }))
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
