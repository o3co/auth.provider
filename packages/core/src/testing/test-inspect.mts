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

import type { OrderedRouteContribution } from "../boot/types.mjs";
import type {
	ExchangeTokenValidator,
	FederationProvider,
	GrantHandler,
} from "../modules/manifest/contributes-map.mjs";

/**
 * Read-only inspection surface for tests. Per A2-γ §7.2: NEVER exposed on the
 * production AppHandle. The `createTestApp` factory attaches an instance of
 * this interface to the returned handle for fixture noise reduction.
 *
 * Stability: additive evolution only. Adding new entries is a minor; signature
 * changes on existing entries are major.
 */
export interface TestInspect {
	readonly grants: ReadonlyMap<string, GrantHandler>;
	readonly federations: ReadonlyMap<string, FederationProvider>;
	readonly tokenExchangeValidators: ReadonlyMap<string, ExchangeTokenValidator>;
	readonly routes: readonly OrderedRouteContribution[];
}
