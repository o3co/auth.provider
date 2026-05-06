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
import {
	type AppConfig,
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenFamilyRotationModule,
	type Module,
} from "@o3co/auth-provider-core";
import { googleFederationModule } from "@o3co/auth-provider-federation-google";
import {
	oauthAuthorizationModule,
	oauthModule,
	oauthSessionModule,
} from "@o3co/auth-provider-oauth";
import { redisRefreshTokenFamilyStoreModule } from "@o3co/auth-provider-redis";
import { sessionModule, sessionStoreModule } from "@o3co/auth-provider-session";
import {
	googleFederationConfigModule,
	keyStoreModule,
	refreshTokenFamilyClientModule,
	repositoriesModule,
	storesModule,
} from "./modules.mjs";

/**
 * Test-only overrides allowing the smoke test to substitute in-memory
 * implementations of the file-system-backed modules. Production callers
 * should not pass overrides; the defaults match the standalone scaffold.
 */
export interface BuildModulesOverrides {
	readonly keyStoreModule?: Module;
	readonly repositoriesModule?: Module;
	readonly storesModule?: Module;
	/**
	 * D-2 v2: override BOTH the RT family client module AND the RT family
	 * store module as a unit. Default:
	 * `[refreshTokenFamilyClientModule, redisRefreshTokenFamilyStoreModule]`.
	 *
	 * Smoke tests / unit tests that don't want to open an ioredis connection
	 * pass `[memoryRefreshTokenFamilyStoreModule]` here (no client module
	 * needed for the memory store). The override REPLACES the entire pair —
	 * passing a single-element array drops the client module too.
	 */
	readonly refreshTokenFamilyModules?: readonly Module[];
}

/**
 * Compose the standalone v0.5.0 module list from `config`. Splitting this
 * out of `app.mts` keeps the composition root testable: a smoke test can
 * verify that disabling a federation removes its module pair from the
 * manifest without spinning up a full HTTP server.
 *
 * Federation gating: `googleFederationModule` requires `googleFederationConfig`,
 * which `googleFederationConfigModule` produces by reading
 * `config.federations.google`. When google is disabled (or the section is
 * absent), the config-bridge module's provider throws — so the entire pair
 * MUST be conditionally included at composition time, not gated inside the
 * provider.
 */
export function buildModules(config: AppConfig, overrides: BuildModulesOverrides = {}): Module[] {
	const googleEnabled =
		(config.federations?.google as { enabled?: boolean } | undefined)?.enabled === true;

	return [
		// D-5: sessionStoreModule wires the express-session middleware into the
		// boot-planner-managed lifecycle. **Mount order is enforced by this
		// list position (declarationIndex tie-breaking)** — the module
		// intentionally has no `before`/`after` clause, so it MUST be listed
		// ahead of every session-consuming module here. Do not reorder.
		sessionStoreModule,
		oauthModule({ config }),
		oauthSessionModule({ config }),
		oauthAuthorizationModule({ config }),
		sessionModule,
		...(googleEnabled ? [googleFederationModule, googleFederationConfigModule] : []),
		overrides.keyStoreModule ?? keyStoreModule,
		overrides.repositoriesModule ?? repositoriesModule,
		overrides.storesModule ?? storesModule,
		// D-2 v2 / OR-1: default to the Redis-backed RT family store + the
		// ioredis client module that supplies it. Multi-replica deployments
		// require a shared Redis instance — without this swap each replica
		// holds families in-process and clients receive `invalid_grant` on
		// every cross-replica refresh. The override path replaces the pair
		// entirely (typically with `[memoryRefreshTokenFamilyStoreModule]`
		// for unit tests that don't want a real ioredis connection).
		...(overrides.refreshTokenFamilyModules ?? [
			refreshTokenFamilyClientModule,
			redisRefreshTokenFamilyStoreModule,
		]),
		defaultRefreshTokenFamilyRotationModule,
		defaultRefreshTokenFamilyRevocationModule,
	];
}
