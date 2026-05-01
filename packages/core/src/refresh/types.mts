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

export type RefreshTokenRotateOutcome =
	| { readonly outcome: "rotated" }
	| { readonly outcome: "replayed"; readonly familyId: string }
	| { readonly outcome: "unknown" }
	| { readonly outcome: "revoked" };

export interface RefreshTokenStoreBase {
	readonly kind: string;

	/**
	 * Atomically consume previousJti and register newJti. See spec Section
	 * 2.4 for the full outcome matrix.
	 */
	rotate(
		previousJti: string | null,
		newJti: string,
		familyId: string,
		expiresAt: Date,
	): Promise<RefreshTokenRotateOutcome>;

	isFamilyRevoked(familyId: string): Promise<boolean>;

	revokeFamily(familyId: string): Promise<void>;
}

export type RefreshTokenStoreFactory = AdapterFactory<RefreshTokenStoreBase>;

// ---------------------------------------------------------------------------
// ComponentMap slot declaration (per A2-α §6.1)
//
// `refreshTokenStore` is an optional v0.4.x-shape component still consumed
// by `oauth/src/routes.mts` (introspect family-revocation lookup, userinfo
// refresh-token handling, logout cascade). Phase 6 (A3) introduced the
// `refreshTokenRotation`/`refreshTokenFamilyStore`/`refreshTokenFamilyRevocation`
// triple as the v0.5.0 successor; migration of routes.mts to consume the
// triple is a follow-on task. Until then, this slot remains live so
// downstream callers can wire it through the v0.5.0 DI graph.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly refreshTokenStore?: RefreshTokenStoreBase;
	}
}
