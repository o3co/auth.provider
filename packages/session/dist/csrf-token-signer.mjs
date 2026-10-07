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
 * The CSRF token's signer over the session secret: the `csrfTokenSigner` slot
 * the session store's module provides from `session-store.secret`, and what a
 * composition that mounts its own cookie session provides in its place.
 *
 * The key is the HKDF-SHA256 expansion of the secret (no salt, info
 * {@link CSRF_KEY_INFO}, 32 bytes), so a token's signature is never a session
 * cookie's signature nor an oracle for one. A signature is the HMAC-SHA256 of
 * the payload under that key, base64url without padding. A token verifies for
 * as long as the deployment keeps its secret and this derivation holds; a
 * fixed vector in this package's tests pins the derivation.
 */
import { createHmac, hkdfSync } from "node:crypto";
import { assertSecretEntropy } from "@o3co/auth-provider-core";
import { constantTimeEquals } from "./internal/constantTimeEquals.mjs";
/**
 * HKDF `info` string. The version suffix is what a change of the token's
 * format bumps, to invalidate every token in flight in one move.
 */
const CSRF_KEY_INFO = "o3co.auth.provider/session-csrf/v1";
/**
 * The signer of the CSRF token under `secret`, the session cookie's secret.
 * Neither the secret nor the key is reachable from what it answers: a frozen
 * plain object carrying `sign` and `verify` alone. `verify` compares in
 * constant time and answers `false` for anything that is not a string.
 *
 * The secret is held to the floor the session store's schema holds
 * `session-store.secret` to (`assertSecretEntropy`), since a composition
 * without the session store's module calls this with a secret no schema has
 * read.
 */
export const createSessionCsrfTokenSigner = (secret) => {
    assertSecretEntropy(secret, {
        configKey: "session-store.secret",
        envVar: "SESSION_STORE_SECRET",
    });
    const key = Buffer.from(hkdfSync("sha256", secret, "", CSRF_KEY_INFO, 32));
    const sign = (payload) => createHmac("sha256", key).update(payload, "utf8").digest("base64url");
    return Object.freeze({
        sign,
        verify: (payload, signature) => {
            if (typeof payload !== "string" || typeof signature !== "string")
                return false;
            return constantTimeEquals(signature, sign(payload));
        },
    });
};
