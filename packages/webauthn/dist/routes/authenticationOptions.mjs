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
import { generateAuthenticationOptionsForUser } from "../internal/options.mjs";
// ---------------------------------------------------------------------------
// Body schema
// ---------------------------------------------------------------------------
const bodySchema = z.object({
    userId: z.string().optional(),
});
// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------
/**
 * Creates an Express RequestHandler for POST /oauth/webauthn/authentication/options.
 *
 * Unauthenticated — no req.webauthnSubject check. Rate-limit middleware is
 * composed externally by the module router (Task 31).
 *
 * @param deps - Injected dependencies (config, challengeStore, credentialStore).
 * @returns RequestHandler suitable for mounting on an Express router.
 */
export function createAuthenticationOptionsHandler(deps) {
    return async (req, res) => {
        // Validate body: userId must be a string if present.
        const parsed = bodySchema.safeParse(req.body ?? {});
        if (!parsed.success) {
            res.status(400).json({
                error: "invalid_request",
                error_description: "userId must be a string",
            });
            return;
        }
        const { userId } = parsed.data;
        // Resolve allowCredentials from the credential store when userId is given.
        // Existence-leak mitigation: same 200 and no error-shape leak regardless
        // of whether userId maps to a real user or not.
        // Limitation: when userId IS provided AND has credentials, allowCredentials
        // is non-empty — distinguishable from the no-credentials case by shape.
        // Full enumeration resistance: use discoverable flow (omit userId) or apply
        // rate-limiting (S10/S15) at the module-wiring layer.
        const allowCredentials = userId !== undefined ? await deps.credentialStore.listByUserId(userId) : [];
        // Generate a fresh 32-byte random challenge for this ceremony.
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        // Generate the PublicKeyCredentialRequestOptionsJSON.
        // Empty allowCredentials → discoverable-credentials flow (SimpleWebAuthn
        // omits the field from the JSON per spec §2.4 when undefined is passed).
        const options = await generateAuthenticationOptionsForUser({
            config: deps.config,
            allowCredentials,
            challenge,
        });
        // Store the challenge under the fixed, non-user-scoped namespace.
        // userId is resolved post-assertion from the credential record — the
        // authenticator identifies the user, not the client request.
        const expiresAtMs = Date.now() + deps.config.challengeTtlMs;
        await deps.challengeStore.issue("webauthn:authentication", options.challenge, expiresAtMs);
        res.status(200).json(options);
    };
}
