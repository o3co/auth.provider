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
	defaultRefreshTokenRotationModule,
	type Module,
	memoryRefreshTokenFamilyStoreModule,
} from "@o3co/auth-provider-core";
import { googleFederationModule } from "@o3co/auth-provider-federation-google";
import {
	oauthAuthorizationModule,
	oauthModule,
	oauthSessionModule,
} from "@o3co/auth-provider-oauth";
import { sessionModule } from "@o3co/auth-provider-session";
import {
	googleFederationConfigModule,
	keyStoreModule,
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
		oauthModule({ config }),
		oauthSessionModule({ config }),
		oauthAuthorizationModule({ config }),
		sessionModule,
		...(googleEnabled ? [googleFederationModule, googleFederationConfigModule] : []),
		overrides.keyStoreModule ?? keyStoreModule,
		overrides.repositoriesModule ?? repositoriesModule,
		overrides.storesModule ?? storesModule,
		memoryRefreshTokenFamilyStoreModule,
		defaultRefreshTokenRotationModule,
		defaultRefreshTokenFamilyRevocationModule,
	];
}
