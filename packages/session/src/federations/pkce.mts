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
 * The PKCE code verifier the federation start route mints and stores for a
 * transaction (RFC 7636 §4.1). The challenge an adapter derives from it is
 * core's `codeChallenge`, because computing it is the adapter's job and not
 * this router's.
 */

import { randomBytes } from "node:crypto";

/** RFC 7636 §4.1: high-entropy URL-safe random string, 43 chars from 32 bytes base64url. */
export function generateCodeVerifier(): string {
	return randomBytes(32).toString("base64url");
}
