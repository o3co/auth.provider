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
import { type AppConfig, defineModule, type Module } from "@o3co/auth-provider-core";
import { createSessionGrant } from "./grants/session.mjs";

/**
 * Declarative manifest for the session grant.
 *
 * Per A2-γ §3.2.3: the v0.4.x `oauthSessionModule({ clientRepository })` factory
 * whose `init(ctx)` conditionally called `ctx.grantRegistry.register("session", ...)` is
 * replaced by a `defineModule(...)` factory whose `contributes.grants.session` entry
 * the boot planner registers automatically.
 *
 * Caller surface: `oauthSessionModule({ clientRepository })` → `oauthSessionModule({ config })`.
 * `clientRepository` and `keyStore` now flow through `requires` from the DI graph.
 *
 * Per the secure-default opt-in discipline (matches `oauthAuthorizationModule`):
 * the session grant registers only when `config.oauth.grants.session.enabled`
 * is the boolean `true`. Absent keys and non-boolean values (e.g. the string
 * `"false"` from HOCON env substitution) are treated as not-enabled and the
 * factory returns a no-op module. A2-α §7.5 permits a module with no
 * `contributes` map.
 */
export const oauthSessionModule = (params: { config: AppConfig }): Module => {
	const grantConfig = (params.config.oauth.grants as Record<string, { enabled?: boolean }>).session;
	if (grantConfig?.enabled !== true) {
		return defineModule({ name: "oauth-session" });
	}
	// Intentionally no `configSchema`: this module reads only slices already
	// declared in `CoreConfigSchema` (`oauth.grants.session.enabled`,
	// `oauth.accessToken.expiresIn`). Adding a symmetric configSchema would
	// be theatre — `composeConfigSchema` already validates these fields via
	// the core schema. Declare a configSchema here only if a future change
	// adds a read of a `config.<full-section>` key that lives in
	// `fullSectionsSchema` (e.g. `config.session`, `config.endpoints`).
	return defineModule({
		name: "oauth-session",
		// `config` is required because createSessionGrant uses config.oauth.accessToken.expiresIn
		// when building the token response for authenticated sessions.
		requires: ["config", "clientRepository", "keyStore"],
		contributes: {
			grants: {
				session: (deps) => createSessionGrant(deps),
			},
		},
	});
};
