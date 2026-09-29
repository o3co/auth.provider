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
 * The RFC 8705 §3.1 certificate thumbprint of a DER-encoded leaf:
 * `base64url(SHA-256(der))` without trailing `=` ("MUST omit all trailing pad
 * '=' characters"). It goes in `cnf.x5t#S256` on the access token and, for
 * public clients, the refresh token (RFC 8705 §4).
 */
export const computeCertThumbprint = (der: Uint8Array): string => {
	// Node's "base64url" already omits padding; the replace guards the MUST
	// should that ever change.
	return createHash("sha256").update(der).digest("base64url").replace(/=+$/, "");
};
