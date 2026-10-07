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
 * What the CRL and OCSP lookups share, defined once so that the two paths cannot
 * drift apart: which of a certificate's `GeneralName` locations is fetched (an
 * absolute HTTP(S) URI), and the issuer key an answer is verified against, which
 * keys both caches.
 */
import { createHash } from "node:crypto";
/** `GeneralName` tag for `uniformResourceIdentifier` (RFC 5280 §4.2.1.6). */
export const GENERAL_NAME_URI = 6;
/** Whether a location is an absolute HTTP(S) URI, the only kind fetched. */
export const isHttpUrl = (value) => /^https?:\/\//i.test(value);
/**
 * The issuer's key, as the hex SHA-256 of its DER `subjectPublicKeyInfo`. A cached
 * answer is keyed by it as well as its source: two CAs can share a subject name — a
 * key rollover keeps the DN — and an answer verified for one must never be handed
 * to a certificate the other issued.
 */
export const issuerKeyId = (issuer) => createHash("sha256")
    .update(new Uint8Array(issuer.subjectPublicKeyInfo.toSchema().toBER(false)))
    .digest("hex");
