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
	defineModule,
	type GrantHandler,
	type Module,
} from "@o3co/auth-provider-core";
import { createAuthorizationGrant } from "./grants/authorization.mjs";
import { createRefreshTokenGrant } from "./grants/refreshToken.mjs";

/**
 * Declarative manifest for the authorization_code and refresh_token grants.
 *
 * Per A2-γ §3.2.2 + Amendment 4 (§1.1.4): the v0.4.x
 * `oauthAuthorizationModule({ codeRepository, clientRepository })` factory
 * whose `init(ctx)` conditionally called `ctx.grantRegistry.register(...)`
 * is replaced by a `defineModule(...)` factory whose `contributes.grants`
 * entries the boot planner registers automatically.
 *
 * Caller surface: `oauthAuthorizationModule({ codeRepository, clientRepository })`
 * → `oauthAuthorizationModule({ config })`.
 * Both repositories now flow through `requires` from the DI graph.
 *
 * Note on optional deps: `refreshTokenStore` (legacy v0.4.x slot, retired by
 * A3) and `grantPolicy` are NOT valid ComponentMap keys in v0.5.0, so they
 * cannot appear in the `optional` array. The grant factories handle their
 * absence gracefully (undefined → feature disabled). Wiring these through the
 * v0.5.0 DI graph is deferred to a follow-on task that updates GrantDependencies
 * to use `refreshTokenRotation` (A3) and the grantPolicyHooks contribution
 * pattern respectively.
 *
 * Theme B (one responsibility per module), Theme D (immutability — no init
 * mutation of ctx), Theme E (structural conditional via factory body).
 */
export const oauthAuthorizationModule = (params: { config: AppConfig }): Module => {
	const grantsCfg = params.config.oauth.grants as Record<string, { enabled?: boolean }>;

	// Per plan Task 3 line 586: type the local grants record as
	// `Record<string, (deps: any) => GrantHandler>` and let `defineModule`
	// infer — the planner accepts the shape. The grant factories
	// (`createAuthorizationGrant`, `createRefreshTokenGrant`) declare stricter
	// `GrantDependencies & {...}` deps shapes pre-Phase-9; redesigning their
	// signatures to consume `ProviderDeps<R, O>` directly is out of scope.
	// biome-ignore lint/suspicious/noExplicitAny: planner-inferred deps shape; see comment above.
	const grants: Record<string, (deps: any) => GrantHandler> = {};
	if (grantsCfg.authorization_code?.enabled !== false) {
		grants.authorization_code = (deps) => createAuthorizationGrant(deps);
	}
	if (grantsCfg.refresh_token?.enabled !== false) {
		grants.refresh_token = (deps) => createRefreshTokenGrant(deps);
	}

	return defineModule({
		name: "oauth-authorization",
		requires: ["config", "clientRepository", "codeRepository", "keyStore"],
		optional: [
			"userSessionStore",
			"sessionRPRegistry", // Amendment 4 (§1.1.4)
			"sessionFamilyIndex", // Amendment 4 (§1.1.4)
			"sessionFederationIndex", // Amendment 4 (§1.1.4)
		],
		contributes: { grants },
	});
};
