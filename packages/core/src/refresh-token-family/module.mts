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
import { createDefaultRefreshTokenFamilyRevocation } from "./revocation.mjs";
import { createDefaultRefreshTokenFamilyRotation } from "./rotation.mjs";

/**
 * Memory-backed RefreshTokenFamilyStore module. Test + dev only — no
 * persistence across restarts. Ships in @o3co/auth-provider-core.
 *
 * Per A3 §8.1.
 */
export const memoryRefreshTokenFamilyStoreModule = defineModule({
	name: "core-refresh-token-family-store-memory",
	provides: {
		refreshTokenFamilyStore: () => createMemoryRefreshTokenFamilyStore(),
	},
});

/**
 * Default RefreshTokenFamilyRotation wrapper module. Composes the storage
 * primitive into the 4-outcome rotation ceremony. Replaceable via DI:
 * consumers wanting custom rotation policy (audit-emitting, grace-period,
 * etc.) provide a module with `provides: { refreshTokenFamilyRotation: ... }`
 * INSTEAD of this one — boot planner enforces uniqueness via
 * BootError({ reason: "duplicate-provides" }).
 *
 * Per A3 §8.1.
 */
export const defaultRefreshTokenFamilyRotationModule = defineModule({
	name: "core-default-refresh-token-family-rotation",
	requires: ["refreshTokenFamilyStore"] as const,
	provides: {
		refreshTokenFamilyRotation: (deps) =>
			createDefaultRefreshTokenFamilyRotation({
				refreshTokenFamilyStore: deps.refreshTokenFamilyStore,
			}),
	},
});

/**
 * Default RefreshTokenFamilyRevocation wrapper module. Composes the
 * storage primitive into the idempotent revoke + read-only check.
 *
 * Per A3 §8.1.
 */
export const defaultRefreshTokenFamilyRevocationModule = defineModule({
	name: "core-default-refresh-token-family-revocation",
	requires: ["refreshTokenFamilyStore"] as const,
	provides: {
		refreshTokenFamilyRevocation: (deps) =>
			createDefaultRefreshTokenFamilyRevocation({
				refreshTokenFamilyStore: deps.refreshTokenFamilyStore,
			}),
	},
});
