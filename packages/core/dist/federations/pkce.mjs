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
/*
 * RFC 7636's S256 transform, the half of PKCE an adapter computes: the
 * `code_challenge` it sends upstream for the verifier the route layer minted
 * and stored. Taking the verifier rather than a pre-computed challenge keeps
 * the transform in one place. No state.
 */
import { createHash } from "node:crypto";
/** RFC 7636 §4.2: S256 transform — BASE64URL(SHA256(verifier)). */
export function codeChallenge(verifier) {
    return createHash("sha256").update(verifier).digest("base64url");
}
