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

import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";

/**
 * Tracks revoked access-token jtis. Optional ComponentMap slot; when present,
 * verifyJwt consults `has(jti)` and `/oauth/revoke` AT path calls `add(jti, expiresAtMs)`.
 *
 * Wave 2 forward-compat: signature is `add(jti, expiresAtMs, options?)`. Wave 1
 * implementations omit `options` parameter and remain valid when Wave 2 adds DPoP `cnf` binding.
 */
export interface AccessTokenDenylist {
	readonly kind: string;
	add(jti: string, expiresAtMs: number): Promise<void>;
	has(jti: string): Promise<boolean>;
}

export type AccessTokenDenylistFactory = AdapterFactory<AccessTokenDenylist>;

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly accessTokenDenylist?: AccessTokenDenylist;
	}
}
