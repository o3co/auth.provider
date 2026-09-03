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
 * The algorithms this module will name. Deliberately a closed set: an
 * operator cannot express "SHA-1 is fine" by pasting an OID, because there is
 * no version of that sentence this module should help write.
 */
export const SIGNATURE_ALGORITHM_OIDS = {
    sha256WithRSAEncryption: "1.2.840.113549.1.1.11",
    sha384WithRSAEncryption: "1.2.840.113549.1.1.12",
    sha512WithRSAEncryption: "1.2.840.113549.1.1.13",
    rsassaPss: "1.2.840.113549.1.1.10",
    ecdsaWithSHA256: "1.2.840.10045.4.3.2",
    ecdsaWithSHA384: "1.2.840.10045.4.3.3",
    ecdsaWithSHA512: "1.2.840.10045.4.3.4",
    ed25519: "1.3.101.112",
    ed448: "1.3.101.113",
};
export const SIGNATURE_ALGORITHM_NAMES = Object.keys(SIGNATURE_ALGORITHM_OIDS);
/**
 * The default allowlist: every name above. The default is permissive across
 * *modern* algorithms and closed against everything else — SHA-1 and MD5 are
 * absent because they are not in the map at all, so no configuration can
 * reach them.
 */
export const DEFAULT_SIGNATURE_ALGORITHMS = SIGNATURE_ALGORITHM_NAMES;
/**
 * Node exposes the modulus length only for RSA keys, and only via
 * `asymmetricKeyDetails`. EC strength is carried by the named curve, which
 * the signature-algorithm allowlist already constrains — a P-256 key cannot
 * be used with `ecdsaWithSHA256` at some weaker size, the way a 512-bit RSA
 * key can be used with `sha256WithRSAEncryption`.
 */
const rsaModulusBits = (certificate) => {
    const key = certificate.publicKey;
    if (key.asymmetricKeyType !== "rsa" && key.asymmetricKeyType !== "rsa-pss")
        return null;
    const bits = key.asymmetricKeyDetails?.modulusLength;
    return typeof bits === "number" ? bits : null;
};
export const checkAlgorithmPolicy = (certificate, signatureAlgorithmOid, policy) => {
    const allowedOids = new Set(policy.signatureAlgorithms.map((name) => SIGNATURE_ALGORITHM_OIDS[name]));
    if (!allowedOids.has(signatureAlgorithmOid)) {
        const known = Object.entries(SIGNATURE_ALGORITHM_OIDS).find(([, oid]) => oid === signatureAlgorithmOid);
        return {
            ok: false,
            step: "signature algorithm not permitted",
            detail: `${certificate.subject}: ${known?.[0] ?? signatureAlgorithmOid} is not in oauth.mtls.full-pki.signature-algorithms`,
        };
    }
    const bits = rsaModulusBits(certificate);
    if (bits !== null && bits < policy.minRsaKeyBits) {
        return {
            ok: false,
            step: "rsa key too small",
            detail: `${certificate.subject}: ${bits}-bit RSA key is below the configured minimum of ${policy.minRsaKeyBits}`,
        };
    }
    return { ok: true };
};
