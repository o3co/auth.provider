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
import path from "node:path";
import {
	type AppConfig,
	createFederationTokenStoreFactory,
	createInMemorySessionFamilyIndex,
	createInMemorySessionFederationIndex,
	createInMemorySessionRPRegistry,
	createInMemoryUserSessionStore,
	createKeyStoreFactory,
	createRepositoryFactories,
	defineModule,
	type Module,
	registerBuiltinFederationTokenStores,
	registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";
import type { GoogleProviderConfig } from "@o3co/auth-provider-federation-google";
import { registerBuiltinAdapters } from "@o3co/auth-provider-foundation";
import {
	redisCodeRepositoryBuilder,
	redisFederationTokenStoreBuilder,
} from "@o3co/auth-provider-redis";
import { extractFederationSection } from "@o3co/auth-provider-session";

/**
 * Helper: turn a v0.4.x { type, [type]: {...} } adapter-config slice into the
 * flat `{ type, ...rest }` shape consumed by AdapterFactory<T>.create().
 *
 * Composition-root concern; not a library export.
 */
function flattenAdapterConfig(
	section: ({ type: string } | { provider: string }) & Record<string, unknown>,
): { type: string } & Record<string, unknown> {
	const selector =
		(section as { type?: string; provider?: string }).type ??
		(section as { provider?: string }).provider;
	if (typeof selector !== "string") {
		throw new TypeError("flattenAdapterConfig: section requires 'type' or 'provider' string");
	}
	const sub = section[selector];
	const flattenedSub =
		typeof sub === "object" && sub !== null && !Array.isArray(sub)
			? (sub as Record<string, unknown>)
			: {};
	return { type: selector, ...flattenedSub };
}

/**
 * KeyStore module — provides the JWT signing KeyStore from config.
 *
 * Per A2-γ §4 worked example. Composition-root-local: the standalone template
 * uses the built-in local/jwks adapters; alternative deployments wire their
 * own KeyStore via a different module of the same shape.
 */
export const keyStoreModule: Module = defineModule({
	name: "standalone:key-store",
	requires: ["config"] as const,
	provides: {
		keyStore: async ({ config }) => {
			const factory = createKeyStoreFactory();
			registerBuiltinKeyStores(factory);
			return factory.create(flattenAdapterConfig((config as AppConfig).oauth.jwt.signingKey));
		},
	},
});

/**
 * Repositories module — provides client / user / code repositories from
 * `config.repositories.*` slices using the built-in adapter factories.
 */
export const repositoriesModule: Module = defineModule({
	name: "standalone:repositories",
	requires: ["config"] as const,
	// D-5 / OR-2 / IH-11: forward `lifecycleRegistrar` into the repository
	// factories so the redis/memory CodeRepository builders can register their
	// disposal callbacks (RedisCodeRepository.quit() and the InMemory GC
	// interval, respectively). Without this, builders' `ctx.lifecycle?.register`
	// is a no-op and the leaks remain.
	optional: ["lifecycleRegistrar"] as const,
	provides: {
		clientRepository: async ({ config, lifecycleRegistrar }) => {
			const ctx = { lifecycle: lifecycleRegistrar };
			const { clientFactory, userFactory } = createRepositoryFactories(ctx);
			registerBuiltinAdapters({ userFactory });
			const slice = flattenAdapterConfig(
				(config as AppConfig).repositories.client as { type: string } & Record<string, unknown>,
			);
			if (typeof slice.path === "string") {
				slice.path = path.resolve(process.cwd(), slice.path);
			}
			return clientFactory.create(slice);
		},
		userRepository: async ({ config, lifecycleRegistrar }) => {
			const ctx = { lifecycle: lifecycleRegistrar };
			const { userFactory } = createRepositoryFactories(ctx);
			registerBuiltinAdapters({ userFactory });
			return userFactory.create(
				flattenAdapterConfig(
					(config as AppConfig).repositories.user as { type: string } & Record<string, unknown>,
				),
			);
		},
		codeRepository: async ({ config, lifecycleRegistrar }) => {
			const ctx = { lifecycle: lifecycleRegistrar };
			const { userFactory, codeFactory } = createRepositoryFactories(ctx);
			registerBuiltinAdapters({ userFactory });
			codeFactory.register("redis", redisCodeRepositoryBuilder);
			return codeFactory.create(
				flattenAdapterConfig(
					(config as AppConfig).repositories.code as { type: string } & Record<string, unknown>,
				),
			);
		},
	},
});

/**
 * Stores module — provides the four-store user-session split + federation
 * token store. The standalone template uses in-memory stores by default; a
 * redis-backed deployment swaps this module for `@o3co/auth-provider-redis`'s
 * equivalent (per A4 §10 / Phase 5).
 */
export const storesModule: Module = defineModule({
	name: "standalone:stores",
	requires: ["config"] as const,
	provides: {
		userSessionStore: () => createInMemoryUserSessionStore(),
		sessionRPRegistry: () => createInMemorySessionRPRegistry(),
		sessionFamilyIndex: () => createInMemorySessionFamilyIndex(),
		sessionFederationIndex: () => createInMemorySessionFederationIndex(),
		federationTokenStore: async ({ config }) => {
			const factory = createFederationTokenStoreFactory();
			registerBuiltinFederationTokenStores(factory);
			factory.register("redis", redisFederationTokenStoreBuilder);
			const slice = (
				config as AppConfig & {
					federationTokenStore?: { type: string } & Record<string, unknown>;
				}
			).federationTokenStore;
			return factory.create(slice ? flattenAdapterConfig(slice) : { type: "memory" });
		},
	},
});

/**
 * Google federation config bridge — supplies the typed `googleFederationConfig`
 * ComponentMap slot from the `config.federations.google` slice.
 *
 * Per `@o3co/auth-provider-federation-google` README. Per-federation modules
 * (Phase 7 A5) consume this slot; the bridge is the standalone composition
 * root's responsibility because the slot's content is consumer-specific.
 */
export const googleFederationConfigModule: Module = defineModule({
	name: "standalone:google-federation-config",
	requires: ["config"] as const,
	provides: {
		googleFederationConfig: ({ config }): GoogleProviderConfig => {
			const slice = extractFederationSection((config as AppConfig).federations, "google");
			if (!slice) {
				throw new Error(
					"federations.google must be enabled with credentials when googleFederationModule is in the manifest",
				);
			}
			const clientId = slice.clientId;
			const clientSecret = slice.clientSecret;
			const callbackURL = slice.callbackURL;
			if (
				typeof clientId !== "string" ||
				typeof clientSecret !== "string" ||
				typeof callbackURL !== "string"
			) {
				throw new Error(
					"federations.google requires clientId, clientSecret, callbackURL when enabled",
				);
			}
			return { clientId, clientSecret, callbackURL };
		},
	},
});
