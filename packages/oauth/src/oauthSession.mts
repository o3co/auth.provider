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
 * Returns true if `value` is an explicit opt-in to enable a feature.
 *
 * HOCON's `passthrough` sub-trees (e.g. `oauth.grants.*`) do not coerce
 * env-var substitution strings to booleans. A resolved `enabled` value can
 * therefore be the string `"true"` (from `OAUTH_GRANTS_SESSION_ENABLED=true`)
 * or the boolean `true` (from an `application.conf` literal). This helper
 * accepts both forms and rejects everything else — including the string
 * `"false"`, the boolean `false`, absent / undefined, and unrelated truthy
 * strings like `"yes"` / `"1"`. Mirrors the same helper in
 * `oauthAuthorization.mts`; both modules apply the same opt-in semantics.
 */
function isExplicitlyEnabled(value: unknown): boolean {
	return value === true || value === "true";
}

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
 * is explicitly truthy (boolean `true` or string `"true"`). Absent keys and
 * other values are treated as not-enabled and the factory returns a no-op
 * module. A2-α §7.5 permits a module with no `contributes` map.
 */
export const oauthSessionModule = (params: { config: AppConfig }): Module => {
	// `oauth.grants` is `z.object({}).passthrough()` in the schema — values
	// arrive unvalidated. The `enabled` field can be the boolean `true` /
	// `false` (HOCON literal) OR the string `"true"` / `"false"` (HOCON env
	// substitution outcome). Typing `enabled` as `unknown` keeps the local
	// cast honest with runtime reality; `isExplicitlyEnabled` performs the
	// strict opt-in narrowing.
	const grantConfig = (params.config.oauth.grants as Record<string, { enabled?: unknown }>).session;
	if (!isExplicitlyEnabled(grantConfig?.enabled)) {
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
