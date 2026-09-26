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
 * Critical extensions processed at any position on the path.
 *
 * - `basicConstraints` — `cA` by the engine, `pathLenConstraint` by
 *   `validate.mts`.
 * - `keyUsage` — `keyCertSign` / `cRLSign` on CAs by the engine,
 *   `digitalSignature` on the leaf by `checkLeafKeyUsage` below.
 * - `nameConstraints`, `certificatePolicies`, `policyMappings`,
 *   `policyConstraints`, `inhibitAnyPolicy` — the engine's RFC 5280 §6.1
 *   name-constraint and policy-tree processing.
 * - `subjectAltName` — the names the engine matches constraints against.
 */
const PROCESSED_ANYWHERE = new Set([
    "2.5.29.19", // basicConstraints
    "2.5.29.15", // keyUsage
    "2.5.29.17", // subjectAltName
    "2.5.29.30", // nameConstraints
    "2.5.29.32", // certificatePolicies
    "2.5.29.33", // policyMappings
    "2.5.29.36", // policyConstraints
    "2.5.29.54", // inhibitAnyPolicy
]);
/**
 * `extendedKeyUsage` is processed **only on the leaf**, by
 * `checkClientLeafProfile` in `pki.mts`.
 *
 * On a CA it would mean EKU chaining — constraining what purposes the CA may
 * issue for — which RFC 5280 does not define and this module does not
 * implement. A CA that marks it critical is asking for enforcement there is
 * none of, so it is refused rather than waved through.
 */
const PROCESSED_ON_LEAF_ONLY = new Set([
    "2.5.29.37", // extKeyUsage
]);
/** OID of `keyUsage`. */
const OID_KEY_USAGE = "2.5.29.15";
/**
 * @param path the validated path, leaf first.
 */
export const checkCriticalExtensions = (path) => {
    for (const [index, certificate] of path.entries()) {
        const isLeaf = index === 0;
        const where = isLeaf ? "leaf" : `CA at depth ${index}`;
        for (const extension of certificate.extensions ?? []) {
            if (!extension.critical)
                continue;
            const recognised = PROCESSED_ANYWHERE.has(extension.extnID) ||
                (isLeaf && PROCESSED_ON_LEAF_ONLY.has(extension.extnID));
            if (!recognised) {
                return {
                    ok: false,
                    step: "unrecognised critical extension",
                    detail: `${where} carries critical extension ${extension.extnID}, which this ` +
                        "validator does not process (RFC 5280 §6.1.2 requires rejection " +
                        "rather than ignoring it)",
                };
            }
            // §6.1.2 has two halves, and the second is easy to lose: the rule
            // covers an unrecognised critical extension "**or** a critical
            // extension that contains information that it cannot process". A
            // recognised OID whose value did not parse is exactly that case —
            // knowing an extension's name is not the same as having read it, and
            // treating a restriction we could not decode as satisfied is how an
            // unparseable `keyUsage` becomes an unconstrained key.
            if (extension.parsedValue === undefined || extension.parsedValue === null) {
                return {
                    ok: false,
                    step: "unparseable critical extension",
                    detail: `${where} carries critical extension ${extension.extnID} whose value ` +
                        "could not be parsed, so the restriction it states cannot be honoured",
                };
            }
        }
    }
    return { ok: true };
};
/**
 * A client certificate authenticates by signing in the TLS handshake, so a
 * `keyUsage` that excludes `digitalSignature` describes a key that cannot do
 * the thing this certificate is being presented to do.
 *
 * Absence is unconstrained, exactly as for `extendedKeyUsage` — RFC 5280
 * §4.2.1.3 makes the extension a restriction, not a grant.
 *
 * This also earns `keyUsage`'s place in `PROCESSED_ANYWHERE`: without it the
 * extension would be listed as recognised while nothing examined it on a
 * leaf.
 */
export const checkLeafKeyUsage = (leaf) => {
    const extension = leaf.extensions?.find((ext) => ext.extnID === OID_KEY_USAGE);
    if (extension === undefined)
        return { ok: true };
    const parsed = extension.parsedValue;
    const bytes = parsed?.valueBlock?.valueHexView;
    // A `keyUsage` that is present but yields no bits is not "unconstrained" —
    // it is a restriction that could not be read. Absence is unconstrained
    // (handled above); an unreadable value is a refusal, because the
    // alternative is treating a stated restriction as satisfied because we
    // could not decode it. `keyUsage` is usually CRITICAL, which makes this the
    // §6.1.2 "cannot process" case as well.
    if (bytes === undefined || bytes.length === 0) {
        return {
            ok: false,
            step: "unparseable leaf keyUsage",
            detail: "the leaf carries a keyUsage extension whose bit string could not be read, " +
                "so the restriction it states cannot be honoured",
        };
    }
    const DIGITAL_SIGNATURE = 0x80;
    if (((bytes[0] ?? 0) & DIGITAL_SIGNATURE) === DIGITAL_SIGNATURE)
        return { ok: true };
    return {
        ok: false,
        step: "leaf keyUsage excludes digitalSignature",
        detail: "the leaf's keyUsage does not permit digitalSignature, which TLS client " +
            "authentication requires (RFC 5280 §4.2.1.3)",
    };
};
