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

import type { Module, ModuleContext } from "@o3co/auth-provider-core";
import { z } from "zod";
import { createDidGrant } from "./did.mjs";
import type { DidDocumentResolver } from "./resolver/types.mjs";
import type { VerifierRegistry } from "./verifiers/registry.mjs";

export const didConfigSchema = z.object({
	did: z
		.object({
			enabled: z.boolean().default(true),
			/** @deprecated Use supportedAlgorithms instead. Kept for backward compatibility. */
			algorithm: z.string().optional(),
			supportedAlgorithms: z.array(z.string()).default(["ed25519_raw"]),
			messageMaxAgeSec: z.coerce.number().default(300),
			allowedAudiences: z.array(z.string()).default([]),
			// Full default object required by zod v4 typing — field-level defaults are authoritative
		})
		.default({
			enabled: true,
			supportedAlgorithms: ["ed25519_raw"],
			messageMaxAgeSec: 300,
			allowedAudiences: [],
		}),
});

export type DidModuleOptions =
	| { resolver: DidDocumentResolver; verifierRegistry?: VerifierRegistry }
	| { resolverFactory: (config: Record<string, unknown>) => DidDocumentResolver; verifierRegistry?: VerifierRegistry };

/**
 * Module that registers the DID grant handler.
 *
 * Accepts either a pre-built resolver or a factory that receives the DID grant
 * config section and returns a resolver.
 *
 * Register with createApp's modules array.
 */
export const oauthDidModule = (options: DidModuleOptions): Module => ({
	name: "oauth-did",
	async init(context: ModuleContext): Promise<void> {
		const grantConfig = (
			context.config.oauth.grants as Record<string, Record<string, unknown> | undefined>
		).did;
		if (grantConfig?.enabled === false) return;

		const resolver =
			"resolver" in options ? options.resolver : options.resolverFactory(grantConfig ?? {});

		const handler = createDidGrant(
			{
				config: context.config,
				keyStore: context.keyStore,
				pathResolver: context.pathResolver,
			},
			{ resolver, verifierRegistry: options.verifierRegistry },
		);
		context.grantRegistry.register("did", handler);
	},
});
