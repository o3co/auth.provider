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
import { z } from "zod";
import type { GrantModule, Module, ModuleContext } from "@o3co/auth-provider-core";
import { createDidGrant } from "./did.mjs";

export const didConfigSchema = z.object({
	did: z.object({
		enabled: z.boolean().default(true),
		algorithm: z.enum([
			"ed25519_raw",
			"ed25519_jws",
			"es256_jws",
			"es256k_jws",
		]).default("ed25519_raw"),
		messageMaxAgeSec: z.coerce.number().default(300),
	// Full default object required by zod v4 typing — field-level defaults are authoritative
	}).default({ enabled: true, algorithm: "ed25519_raw", messageMaxAgeSec: 300 }),
});

/**
 * Legacy GrantModule interface — kept for backward compatibility with
 * GrantRegistry.addModule() pattern.
 */
export const didGrantModule: GrantModule = {
	grants: {
		did: (deps) => createDidGrant(deps),
	},
	configSchema: didConfigSchema,
};

/**
 * @deprecated Use oauthDidModule instead for the new Module interface.
 */
export const didModule = didGrantModule;

/**
 * New Module interface — uses ModuleContext with pathResolver.
 * Register with createApp's modules array.
 */
export const oauthDidModule: Module = {
	name: "oauth-did",
	async init(context: ModuleContext): Promise<void> {
		const grantConfig = (
			context.config.oauth.grants as Record<string, { enabled?: boolean }>
		).did;
		if (grantConfig?.enabled === false) return;

		const handler = createDidGrant({
			config: context.config,
			keyStore: context.keyStore,
			pathResolver: context.pathResolver,
		});
		context.grantRegistry.register("did", handler);
	},
};
