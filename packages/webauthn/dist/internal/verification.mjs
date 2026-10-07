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
import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
export async function verifyWebAuthnAttestation(input) {
    try {
        const verification = await verifyRegistrationResponse({
            response: input.response,
            expectedChallenge: input.expectedChallenge,
            expectedOrigin: [...input.expectedOrigins], // S7: multi-origin support
            expectedRPID: input.expectedRpId,
            // Enforce UV when configured as "required"; otherwise false (hint only).
            // "preferred" and "discouraged" are request hints only — not server-enforced.
            // Cross-refs: Codex Round 2 P1-1 / spec §2.5
            requireUserVerification: (input.userVerification ?? "preferred") === "required",
        });
        if (!verification.verified || !verification.registrationInfo) {
            return { ok: false, reason: "attestation_invalid" };
        }
        const info = verification.registrationInfo;
        return {
            ok: true,
            material: {
                credentialId: info.credential.id,
                publicKey: new Uint8Array(info.credential.publicKey),
                signCount: info.credential.counter,
                // SimpleWebAuthn's AuthenticatorTransportFuture is a superset of our
                // AuthenticatorTransport (adds "cable" and "smart-card"). Cast to
                // unknown first to avoid the direct-super-type assignment error.
                transports: info.credential.transports,
                backedUp: info.credentialBackedUp,
            },
        };
    }
    catch (err) {
        return mapRegistrationError(err);
    }
}
function mapRegistrationError(err) {
    if (err instanceof Error) {
        if (/origin/i.test(err.message))
            return { ok: false, reason: "origin_mismatch" };
        if (/challenge/i.test(err.message))
            return { ok: false, reason: "challenge_mismatch" };
        if (/rp.?id/i.test(err.message))
            return { ok: false, reason: "rp_id_mismatch" };
    }
    return { ok: false, reason: "unknown" };
}
export async function verifyWebAuthnAssertion(input) {
    try {
        const verification = await verifyAuthenticationResponse({
            response: input.response,
            expectedChallenge: input.expectedChallenge,
            expectedOrigin: [...input.expectedOrigins], // S7: multi-origin support
            expectedRPID: input.expectedRpId,
            credential: {
                id: input.credential.credentialId,
                publicKey: input.credential.publicKey,
                counter: input.credential.signCount,
                // Cast: SimpleWebAuthn expects AuthenticatorTransportFuture[]
                // (superset of our AuthenticatorTransport — adds "cable" and
                // "smart-card"). Our stored values are a strict subset; the cast
                // is safe since the common values round-trip without loss.
                // biome-ignore lint/suspicious/noExplicitAny: transport superset cast — see comment
                transports: input.credential.transports,
            },
            // Enforce UV when configured as "required"; otherwise false (hint only).
            // Cross-refs: Codex Round 2 P1-1 / spec §2.5
            requireUserVerification: (input.userVerification ?? "preferred") === "required",
        });
        if (!verification.verified) {
            return { ok: false, reason: "signature_invalid" };
        }
        const newCounter = verification.authenticationInfo.newCounter;
        const stored = input.credential.signCount;
        // §2.4 sign-count corner case: if both stored AND new counters are 0,
        // allow (some authenticators always report 0).
        // SimpleWebAuthn already skips its own counter throw for the 0/0 case
        // (condition: (counter > 0 || credential.counter > 0) && counter <= credential.counter).
        // We still guard here so the return type is explicit.
        if (newCounter === 0 && stored === 0) {
            return { ok: true, newSignCount: 0 };
        }
        // For all other cases: SimpleWebAuthn already throws a counter error
        // when newCounter <= stored (and at least one is > 0), so this guard
        // only fires in edge cases where SimpleWebAuthn returns verified=true
        // but the counter did not increase (should not happen in practice).
        if (newCounter <= stored) {
            return { ok: false, reason: "sign_count_regression" };
        }
        return { ok: true, newSignCount: newCounter };
    }
    catch (err) {
        return mapAuthenticationError(err);
    }
}
function mapAuthenticationError(err) {
    if (err instanceof Error) {
        if (/origin/i.test(err.message))
            return { ok: false, reason: "origin_mismatch" };
        if (/challenge/i.test(err.message))
            return { ok: false, reason: "challenge_mismatch" };
        if (/rp.?id/i.test(err.message))
            return { ok: false, reason: "rp_id_mismatch" };
        if (/counter/i.test(err.message))
            return { ok: false, reason: "sign_count_regression" };
    }
    return { ok: false, reason: "unknown" };
}
