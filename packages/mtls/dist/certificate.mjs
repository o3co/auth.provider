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
import { X509Certificate } from "node:crypto";
/**
 * Parse DER bytes into a `ClientCertificate`, optionally attaching intermediate
 * chain DER entries.
 *
 * Uses `new X509Certificate(der)` from `node:crypto` (Node ≥ 15.6) per
 * RFC 8705 §7.5's mandate to use an established X.509 library rather than
 * a custom parser.
 *
 * Throws a plain `Error` on parse failure — the call site (extractor.mts
 * step 3) wraps it into `MtlsError("cert_decode_failed", …)`.
 *
 * Per Wave 2 Phase 3 spec §5.3 + §6.3.
 */
export const parseDerToCertificate = (der, chain) => {
    // `new X509Certificate(der)` throws DOMException / Error on malformed DER —
    // we let the error propagate unmodified so the call site can wrap it with
    // the correct MtlsReasonCode context.
    const x509 = new X509Certificate(der);
    // Defense-in-depth: copy DER bytes on construction so a downstream
    // caller holding a reference to the input buffer cannot tamper with the
    // thumbprint source after parse (Codex Round 1 Important #4). The
    // `readonly` modifier on the type only protects the property *assignment*,
    // not the underlying byte mutation. Realistic cert size is 1-3KB; one
    // allocation per parse is a free defensive lock-down.
    const derCopy = new Uint8Array(der);
    const chainCopy = chain !== undefined ? chain.map((entry) => new Uint8Array(entry)) : undefined;
    return {
        der: derCopy,
        ...(chainCopy !== undefined ? { chain: chainCopy } : {}),
        parsed: {
            subject: x509.subject,
            issuer: x509.issuer,
            // `validFrom` / `validTo` are ISO 8601 date strings from Node's X509Certificate.
            notBefore: x509.validFrom,
            notAfter: x509.validTo,
        },
    };
};
