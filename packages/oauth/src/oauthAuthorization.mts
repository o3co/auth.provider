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
	createAuthorizationGrant,
	createRefreshTokenGrant,
	type CodeRepository,
	type Module,
	type ModuleContext,
} from "@o3co/auth-provider-core";

export const oauthAuthorizationModule = (params: {
	codeRepository: CodeRepository;
}): Module => ({
	name: "oauth-authorization",
	async init(context: ModuleContext): Promise<void> {
		const grantsConfig = context.config.oauth.grants as Record<
			string,
			{ enabled?: boolean }
		>;

		if (grantsConfig.authorization?.enabled !== false) {
			const handler = createAuthorizationGrant({
				config: context.config,
				keyStore: context.keyStore,
				codeRepository: params.codeRepository,
			});
			context.grantRegistry.register("authorization", handler);
		}

		if (grantsConfig.refresh_token?.enabled !== false) {
			const handler = createRefreshTokenGrant({
				config: context.config,
				keyStore: context.keyStore,
			});
			context.grantRegistry.register("refresh_token", handler);
		}
	},
});
