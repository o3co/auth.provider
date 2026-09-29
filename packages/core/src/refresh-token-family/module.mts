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
import { defineModule } from "../modules/manifest/define-module.mjs";
import { createMemoryRefreshTokenFamilyStore } from "./adapters/memory.mjs";
import { resolveFamilyAccessTokenHorizonMs } from "./retention.mjs";
import { createRefreshTokenFamilyRevocation } from "./revocation.mjs";
import { createRefreshTokenFamilyRotation } from "./rotation.mjs";

/**
 * Memory-backed RefreshTokenFamilyStore module, for tests and development:
 * nothing persists across restarts. A restart forgets every family, revoked
 * ones included, so an access token of a family revoked before it passes the
 * family check until it expires; one reason it is declared replica-unsafe.
 */
export const memoryRefreshTokenFamilyStoreModule = defineModule({
	name: "core-refresh-token-family-store-memory",
	// What forks per replica, quoted into a refused multi-replica boot.
	replicaSafety: {
		unsafe: true,
		reason:
			"refresh-token families fork per replica — rotation replay detection and cascade revoke see only this replica's history, and a restart forgets every revoked family while its access tokens are still valid",
	},
	provides: {
		refreshTokenFamilyStore: () => createMemoryRefreshTokenFamilyStore(),
	},
});

/**
 * Default RefreshTokenFamilyRotation wrapper module: composes the storage
 * primitive into the 4-outcome rotation ceremony. For a custom rotation
 * policy (audit-emitting, grace-period, …), provide
 * `refreshTokenFamilyRotation` from a module used INSTEAD of this one; boot
 * refuses two (`duplicate-provides`).
 */
export const defaultRefreshTokenFamilyRotationModule = defineModule({
	name: "core-default-refresh-token-family-rotation",
	// `config` for the access-token maximum that sizes how long a family
	// revoked on replay is remembered (`retention.mts`).
	requires: ["refreshTokenFamilyStore", "config"] as const,
	provides: {
		refreshTokenFamilyRotation: (deps) =>
			createRefreshTokenFamilyRotation({
				refreshTokenFamilyStore: deps.refreshTokenFamilyStore,
				accessTokenHorizonMs: resolveFamilyAccessTokenHorizonMs(deps.config),
			}),
	},
});

/**
 * Default RefreshTokenFamilyRevocation wrapper module. Composes the
 * storage primitive into the idempotent revoke + read-only check, keeping a
 * revoked record for the configured access-token maximum (`retention.mts`).
 */
export const defaultRefreshTokenFamilyRevocationModule = defineModule({
	name: "core-default-refresh-token-family-revocation",
	requires: ["refreshTokenFamilyStore", "config"] as const,
	provides: {
		refreshTokenFamilyRevocation: (deps) =>
			createRefreshTokenFamilyRevocation({
				refreshTokenFamilyStore: deps.refreshTokenFamilyStore,
				accessTokenHorizonMs: resolveFamilyAccessTokenHorizonMs(deps.config),
			}),
	},
});
