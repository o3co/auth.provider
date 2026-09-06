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
import { createFederationTokenStoreFactory, createInMemorySessionFamilyIndex, createInMemorySessionFederationIndex, createInMemorySessionRPRegistry, createInMemoryUserSessionStore, createKeyStoreFactory, createRepositoryFactories, defineModule, registerBuiltinFederationTokenStores, registerBuiltinKeyStores, } from "@o3co/auth-provider-core";
import { registerBuiltinAdapters } from "@o3co/auth-provider-foundation";
import { redisCodeRepositoryBuilder, redisFederationTokenStoreBuilder, } from "@o3co/auth-provider-redis";
import { extractFederationSection } from "@o3co/auth-provider-session";
/**
 * Helper: turn a v0.4.x { type, [type]: {...} } adapter-config slice into the
 * flat `{ type, ...rest }` shape consumed by AdapterFactory<T>.create().
 *
 * Composition-root concern; not a library export.
 */
function flattenAdapterConfig(section) {
    const selector = section.type ??
        section.provider;
    if (typeof selector !== "string") {
        throw new TypeError("flattenAdapterConfig: section requires 'type' or 'provider' string");
    }
    const sub = section[selector];
    const flattenedSub = typeof sub === "object" && sub !== null && !Array.isArray(sub)
        ? sub
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
export const keyStoreModule = defineModule({
    name: "standalone:key-store",
    requires: ["config"],
    provides: {
        keyStore: async ({ config }) => {
            const factory = createKeyStoreFactory();
            registerBuiltinKeyStores(factory);
            return factory.create(flattenAdapterConfig(config.oauth.jwt.signingKey));
        },
    },
});
/**
 * Repositories module — provides client / user / code repositories from
 * `config.repositories.*` slices using the built-in adapter factories.
 */
export const repositoriesModule = defineModule({
    name: "standalone:repositories",
    requires: ["config"],
    provides: {
        clientRepository: async ({ config }) => {
            const { clientFactory, userFactory } = createRepositoryFactories();
            registerBuiltinAdapters({ userFactory });
            const slice = flattenAdapterConfig(config.repositories.client);
            if (typeof slice.path === "string") {
                slice.path = path.resolve(process.cwd(), slice.path);
            }
            return clientFactory.create(slice);
        },
        userRepository: async ({ config }) => {
            const { userFactory } = createRepositoryFactories();
            registerBuiltinAdapters({ userFactory });
            return userFactory.create(flattenAdapterConfig(config.repositories.user));
        },
        codeRepository: async ({ config }) => {
            const { userFactory, codeFactory } = createRepositoryFactories();
            registerBuiltinAdapters({ userFactory });
            codeFactory.register("redis", redisCodeRepositoryBuilder);
            return codeFactory.create(flattenAdapterConfig(config.repositories.code));
        },
    },
});
/**
 * Stores module — provides the four-store user-session split + federation
 * token store. The standalone template uses in-memory stores by default; a
 * redis-backed deployment swaps this module for `@o3co/auth-provider-redis`'s
 * equivalent (per A4 §10 / Phase 5).
 */
export const storesModule = defineModule({
    name: "standalone:stores",
    requires: ["config"],
    provides: {
        userSessionStore: () => createInMemoryUserSessionStore(),
        sessionRPRegistry: () => createInMemorySessionRPRegistry(),
        sessionFamilyIndex: () => createInMemorySessionFamilyIndex(),
        sessionFederationIndex: () => createInMemorySessionFederationIndex(),
        federationTokenStore: async ({ config }) => {
            const factory = createFederationTokenStoreFactory();
            registerBuiltinFederationTokenStores(factory);
            factory.register("redis", redisFederationTokenStoreBuilder);
            const slice = config.federationTokenStore;
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
export const googleFederationConfigModule = defineModule({
    name: "standalone:google-federation-config",
    requires: ["config"],
    provides: {
        googleFederationConfig: ({ config }) => {
            const slice = extractFederationSection(config.federations, "google");
            if (!slice) {
                throw new Error("federations.google must be enabled with credentials when googleFederationModule is in the manifest");
            }
            const clientId = slice.clientId;
            const clientSecret = slice.clientSecret;
            const callbackURL = slice.callbackURL;
            if (typeof clientId !== "string" ||
                typeof clientSecret !== "string" ||
                typeof callbackURL !== "string") {
                throw new Error("federations.google requires clientId, clientSecret, callbackURL when enabled");
            }
            return { clientId, clientSecret, callbackURL };
        },
    },
});
