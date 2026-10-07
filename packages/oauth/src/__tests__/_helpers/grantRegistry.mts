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
 * The `grantHandlerResolver` boot projects, for a grant built by hand: a
 * frozen registry holding each grant type named, with a handler that is only
 * looked up. The authorization_code grant issues a refresh token only while
 * the registry holds `refresh_token`, so a test of the ordinary exchange
 * hands it `registeredGrants("refresh_token")`.
 */

import type { GrantHandler, GrantHandlerResolver } from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";

const lookedUpOnly: GrantHandler = {
	async handle() {
		throw new Error("this grant is only looked up in the registry, never run");
	},
};

export function registeredGrants(...grantTypes: readonly string[]): GrantHandlerResolver {
	const registry = new GrantRegistry();
	for (const grantType of grantTypes) registry.register(grantType, lookedUpOnly);
	registry.freeze();
	return registry;
}
