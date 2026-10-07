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
import { createHmac, timingSafeEqual } from "node:crypto";
import { MIN_SECRET_ENTROPY_BYTES, measureSecretEntropyBytes } from "@o3co/auth-provider-core";
export const DEFAULT_DPOP_NONCE_TTL_SECONDS = 300;
export function createDPoPNonceIssuer(options) {
    const secret = typeof options.secret === "string" ? new TextEncoder().encode(options.secret) : options.secret;
    const keyMaterialBytes = typeof options.secret === "string"
        ? measureSecretEntropyBytes(options.secret)
        : options.secret.byteLength;
    if (keyMaterialBytes < MIN_SECRET_ENTROPY_BYTES) {
        throw new Error(`createDPoPNonceIssuer: secret must carry at least ${MIN_SECRET_ENTROPY_BYTES} bytes of key ` +
            `material (it carries ${keyMaterialBytes}) — a nonce is only as unforgeable as the key that signs it.`);
    }
    const ttlSeconds = options.ttlSeconds ?? DEFAULT_DPOP_NONCE_TTL_SECONDS;
    if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
        throw new Error("createDPoPNonceIssuer: ttlSeconds must be a positive integer");
    }
    const now = options.now ?? Date.now;
    const bucketNow = () => Math.floor(now() / 1000 / ttlSeconds);
    const macOf = (bucket) => createHmac("sha256", secret).update(`dpop-nonce:${bucket}`).digest();
    const encode = (bucket) => `${bucket}.${macOf(bucket).toString("base64url")}`;
    return {
        issue: () => encode(bucketNow()),
        verify: (nonce) => {
            const dot = nonce.indexOf(".");
            if (dot <= 0)
                return false;
            const bucket = Number(nonce.slice(0, dot));
            if (!Number.isInteger(bucket))
                return false;
            const current = bucketNow();
            if (bucket !== current && bucket !== current - 1)
                return false;
            const presented = Buffer.from(nonce.slice(dot + 1), "base64url");
            const expected = macOf(bucket);
            return presented.length === expected.length && timingSafeEqual(presented, expected);
        },
    };
}
