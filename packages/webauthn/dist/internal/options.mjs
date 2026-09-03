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
import { generateAuthenticationOptions as swGenAuth, generateRegistrationOptions as swGenReg, } from "@simplewebauthn/server";
// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------
export async function generateRegistrationOptionsForUser(args) {
    // SimpleWebAuthn v13.1.1 removed "indirect" from attestationType.
    // Map "indirect" → "none" (least-privilege fallback).
    const attestationType = args.config.attestationPreference === "indirect"
        ? "none"
        : args.config.attestationPreference;
    return swGenReg({
        rpName: args.config.rpName,
        rpID: args.config.rpId,
        // TextEncoder produces a Uint8Array from the opaque userId string.
        // SimpleWebAuthn accepts Uint8Array for userID and encodes it as base64url
        // in the returned PublicKeyCredentialCreationOptionsJSON.
        userID: new TextEncoder().encode(args.userId),
        userName: args.userName,
        userDisplayName: args.userDisplayName,
        attestationType,
        excludeCredentials: args.excludeCredentials.map((c) => ({
            id: c.credentialId,
            // Cast: SimpleWebAuthn expects AuthenticatorTransportFuture[]
            // (superset of our AuthenticatorTransport — adds "cable" and
            // "smart-card"). Our stored values are a strict subset; the cast
            // is safe since the common values round-trip without loss.
            // biome-ignore lint/suspicious/noExplicitAny: transport superset cast — see comment
            transports: c.transports,
        })),
        authenticatorSelection: {
            userVerification: args.config.userVerification,
            // residentKey: "preferred" enables discoverable credentials by default
            // per WebAuthn §2.4 / spec §2.4. Deployers needing strict passkey-only
            // enforcement may override to "required" via a future config field.
            residentKey: "preferred",
        },
        challenge: args.challenge,
    });
}
// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------
export async function generateAuthenticationOptionsForUser(args) {
    return swGenAuth({
        rpID: args.config.rpId,
        userVerification: args.config.userVerification,
        // Empty array → discoverable flow: pass undefined so SimpleWebAuthn omits
        // allowCredentials from the JSON (rather than sending an empty list, which
        // some browsers interpret differently from absent).
        allowCredentials: args.allowCredentials.length === 0
            ? undefined
            : args.allowCredentials.map((c) => ({
                id: c.credentialId,
                // biome-ignore lint/suspicious/noExplicitAny: transport superset cast — see comment on registration helper
                transports: c.transports,
            })),
        challenge: args.challenge,
    });
}
