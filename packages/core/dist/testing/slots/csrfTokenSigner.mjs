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
 * The test double of the `csrfTokenSigner` slot. `createTestCsrfTokenSigner`
 * keeps the slot's contract — a base64url signature within the bounds core
 * exports, the same for the same payload, a `verify` that never throws, and
 * a frozen plain object carrying `sign` and `verify` alone — with a random
 * key. The contract suite is `@o3co/auth-provider-test-kit`'s. Published on
 * `@o3co/auth-provider-core/testing`.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
/** A fixed-length digest of `value`, so two values of any lengths compare in constant time. */
const digestOf = (value) => createHash("sha256").update(value, "utf8").digest();
/**
 * A signer over a random 32-byte key drawn when it is built: HMAC-SHA256 of
 * the payload, base64url; `verify` compares fixed-length digests of the two
 * signatures with `timingSafeEqual` and answers `false` for anything that is
 * not a string. Frozen. Two doubles sign alike never.
 */
export function createTestCsrfTokenSigner() {
    const key = randomBytes(32);
    const sign = (payload) => createHmac("sha256", key).update(payload, "utf8").digest("base64url");
    return Object.freeze({
        sign,
        verify: (payload, signature) => {
            if (typeof payload !== "string" || typeof signature !== "string")
                return false;
            return timingSafeEqual(digestOf(sign(payload)), digestOf(signature));
        },
    });
}
