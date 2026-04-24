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
import type {
	AppConfig,
	ClientRepository,
	CodeRepository,
	Module,
	ModuleContext,
} from "@o3co/auth-provider-core";
import { createAuthorizationGrant } from "./grants/authorization.mjs";
import { createRefreshTokenGrant } from "./grants/refreshToken.mjs";

export const oauthAuthorizationModule = (params: {
	codeRepository: CodeRepository;
	clientRepository: ClientRepository;
}): Module => ({
	name: "oauth-authorization",
	async init(context: ModuleContext): Promise<void> {
		const config = context.config as AppConfig;
		const grantsConfig = config.oauth.grants as Record<string, { enabled?: boolean }>;

		if (grantsConfig.authorization_code?.enabled !== false) {
			const handler = createAuthorizationGrant({
				config,
				keyStore: context.keyStore,
				codeRepository: params.codeRepository,
				clientRepository: params.clientRepository,
				refreshTokenStore: context.refreshTokenStore,
				userSessionStore: context.userSessionStore,
				grantPolicy: context.grantPolicy,
			});
			context.grantRegistry.register("authorization_code", handler);
		}

		if (grantsConfig.refresh_token?.enabled !== false) {
			const handler = createRefreshTokenGrant({
				config,
				keyStore: context.keyStore,
				refreshTokenStore: context.refreshTokenStore,
				userSessionStore: context.userSessionStore,
				grantPolicy: context.grantPolicy,
			});
			context.grantRegistry.register("refresh_token", handler);
		}
	},
});
