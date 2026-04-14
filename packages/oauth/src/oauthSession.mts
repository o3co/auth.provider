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
	Module,
	ModuleContext,
} from "@o3co/auth-provider-core";
import { createSessionGrant } from "./grants/session.mjs";

export const oauthSessionModule = (params: {
	clientRepository: ClientRepository;
}): Module => ({
	name: "oauth-session",
	async init(context: ModuleContext): Promise<void> {
		const config = context.config as AppConfig;
		const grantConfig = (
			config.oauth.grants as Record<string, { enabled?: boolean }>
		).session;
		if (grantConfig?.enabled === false) return;

		const handler = createSessionGrant({
			config,
			keyStore: context.keyStore,
			clientRepository: params.clientRepository,
		});
		context.grantRegistry.register("session", handler);
	},
});
