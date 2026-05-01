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

/**
 * Resolves a module specifier to a URL/path that can be passed to dynamic import().
 * Typically set to import.meta.resolve at the application level.
 */
export type PathResolver = (specifier: string) => string;

/**
 * Minimal structural type for a federation provider as seen from
 * `ContributesMap.federations` consumers via the `federationProviders`
 * synthetic key.
 *
 * `FederationProvider` from `@o3co/auth-provider-session` carries the full
 * capability surface (`buildAuthorizationUrl`, `exchangeCode`, optional
 * `endSession` / `mapClaims` / `refreshToken`). Core cannot import that type
 * directly — it would create a circular dependency. This structural alias
 * captures only the shape that `oauth/routes` and similar core-adjacent
 * consumers use when looking up providers from the synthetic-key map. They
 * narrow with `instanceof` / type-guard helpers (`supportsLogout`,
 * `supportsRefresh`) after reading from the map.
 */
export interface FederationProviderHandle {
	readonly name: string;
}
