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
import { createAuthorizationGrant } from "./authorization.mjs";
import { createDidGrant } from "./did.mjs";
import { createRefreshTokenGrant } from "./refreshToken.mjs";
import { createSessionGrant } from "./session.mjs";
import type { GrantDependencies, GrantHandler } from "./types.mjs";

export class GrantRegistry {
	private handlers = new Map<string, GrantHandler>();

	register(grantType: string, handler: GrantHandler): void {
		this.handlers.set(grantType, handler);
	}

	get(grantType: string): GrantHandler | undefined {
		return this.handlers.get(grantType);
	}

	cleanup(): void {
		for (const handler of this.handlers.values()) {
			handler.cleanup?.();
		}
	}
}

export const createGrantRegistry = (deps: GrantDependencies): GrantRegistry => {
	const registry = new GrantRegistry();

	if (deps.config.oauth.grants.session.enabled) {
		registry.register("session", createSessionGrant(deps));
	}
	if (deps.config.oauth.grants.authorization.enabled) {
		registry.register("authorization", createAuthorizationGrant(deps));
	}
	if (deps.config.oauth.grants.refresh_token.enabled) {
		registry.register("refresh_token", createRefreshTokenGrant(deps));
	}
	if (deps.config.oauth.grants.did.enabled) {
		registry.register("did", createDidGrant(deps));
	}

	return registry;
};
