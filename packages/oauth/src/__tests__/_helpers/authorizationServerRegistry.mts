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
import type { GrantHandler } from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";

/**
 * A grant registry holding a stand-in `authorization_code` grant, which is
 * what makes `createOAuthRouter` mount `/authorize`. A test of `/authorize`
 * alone never dispatches to it; one that also dispatches at `/oauth/token`
 * registers its own grants beside it.
 */
export function authorizationServerRegistry(): GrantRegistry {
	const registry = new GrantRegistry();
	registry.register("authorization_code", {} as GrantHandler);
	return registry;
}
