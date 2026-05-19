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
import { createHash } from "node:crypto";

/**
 * Compute the RFC 8705 §3.1 certificate thumbprint from the DER-encoded
 * leaf certificate.
 *
 * The thumbprint is `base64url(SHA-256(der))` with trailing `=` pad
 * characters stripped — the RFC 8705 §3.1 normative requirement is:
 *   "The base64url-encoded value MUST omit all trailing pad '=' characters."
 *
 * This value is placed in `cnf.x5t#S256` on the issued access token and (for
 * public clients) on the issued refresh token (RFC 8705 §4 SHOULD).
 *
 * Per Wave 2 Phase 3 spec §6.6 + RFC 8705 §3.1.
 */
export const computeCertThumbprint = (der: Uint8Array): string => {
	// `digest()` returns a Buffer in Node — Buffer inherits from Uint8Array,
	// and `toString("base64url")` performs the RFC 4648 §5 URL-safe encoding.
	// Node's `"base64url"` already omits trailing `=` padding, but the explicit
	// `.replace(/=+$/, "")` is a defensive guard against future Node changes
	// that might re-introduce padding (per spec §6.6 comment).
	return createHash("sha256").update(der).digest("base64url").replace(/=+$/, "");
};
