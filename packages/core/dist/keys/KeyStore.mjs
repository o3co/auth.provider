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
import { createSecretKey } from "node:crypto";
import { importPKCS8, importSPKI, SignJWT } from "jose";
export async function createAsymmetricKeyStore(options) {
    const { algorithm, kid, privateKeyPem, publicKeyPem, previousKeys = [] } = options;
    // Validate kid uniqueness
    const allKids = [kid, ...previousKeys.map((k) => k.kid)];
    const duplicates = allKids.filter((k, i) => allKids.indexOf(k) !== i);
    if (duplicates.length > 0) {
        throw new Error(`Duplicate kid values: ${[...new Set(duplicates)].join(", ")}`);
    }
    const privateKey = await importPKCS8(privateKeyPem, algorithm);
    const publicKey = await importSPKI(publicKeyPem, algorithm);
    // Import all previous public keys upfront
    const resolvedPrevious = await Promise.all(previousKeys.map(async (prev) => ({
        kid: prev.kid,
        publicKey: (await importSPKI(prev.publicKeyPem, algorithm)),
        expiresAt: prev.expiresAt,
    })));
    return {
        algorithm,
        async sign({ claims, header }) {
            return await new SignJWT(claims)
                .setProtectedHeader({
                alg: algorithm,
                kid,
                ...(header?.typ ? { typ: header.typ } : {}),
            })
                .sign(privateKey);
        },
        getSigningKidFallback() {
            return kid;
        },
        async getVerificationKeys() {
            const now = new Date();
            const active = resolvedPrevious.filter((k) => k.expiresAt > now);
            return [{ kid, publicKey }, ...active];
        },
        async getVerificationKey(requestedKid) {
            if (requestedKid === kid) {
                return publicKey;
            }
            const prev = resolvedPrevious.find((k) => k.kid === requestedKid);
            if (!prev) {
                throw new Error(`Unknown kid: ${requestedKid}`);
            }
            if (prev.expiresAt <= new Date()) {
                throw new Error(`Expired kid: ${requestedKid}`);
            }
            return prev.publicKey;
        },
    };
}
export function createSymmetricKeyStore(secret, kid = "v0") {
    const secretKey = createSecretKey(Buffer.from(secret));
    return {
        algorithm: "HS256",
        async sign({ claims, header }) {
            return await new SignJWT(claims)
                .setProtectedHeader({
                alg: "HS256",
                kid,
                ...(header?.typ ? { typ: header.typ } : {}),
            })
                .sign(secretKey);
        },
        getSigningKidFallback() {
            return kid;
        },
        async getVerificationKeys() {
            return [{ kid, publicKey: secretKey }];
        },
        async getVerificationKey(requestedKid) {
            if (requestedKid !== kid) {
                throw new Error(`Unknown kid: ${requestedKid}`);
            }
            return secretKey;
        },
    };
}
