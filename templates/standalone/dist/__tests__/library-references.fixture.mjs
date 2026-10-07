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
/**
 * The libraries' layers beneath the template's own files, for a test that
 * resolves its configuration by hand: the `reference.conf` of every package
 * the template composes a module from, core's last, as `app.mts` layers them;
 * the resolution handed to both phases at once; and what that resolution
 * captures of the renamed variables.
 */
import { fileURLToPath } from "node:url";
import { memoryRateLimiterModule, moduleReferences, } from "@o3co/auth-provider-core";
import { CORE_RELOCATIONS, renamedVariableCaptures } from "@o3co/auth-provider-core/testing";
import { federationGrantsModules } from "@o3co/auth-provider-federation-grants";
import { oauthAuthorizationGrantsModule, oauthEndpointsModule, oauthSessionGrantModule, } from "@o3co/auth-provider-oauth";
import { redisCodeRepositoryModule, redisFederationGrantStoreModule, redisRateLimiterModule, redisRefreshTokenFamilyStoreModule, } from "@o3co/auth-provider-redis";
import { sessionModule, sessionStoreModule } from "@o3co/auth-provider-session";
import { empty, parseFile } from "@o3co/ts.hocon";
import { readAdapters } from "../adapters.mjs";
import { readSwitches } from "../configPath.mjs";
import { httpModule, inMemoryCodeRepositoryModule, keyStoreModule, loggingModule, repositoriesModuleFor, standaloneRedisClientsModule, templateReference, } from "../modules.mjs";
import { isPlainSection } from "../sections.mjs";
/** The oauth package's modules: none reads the configuration it is handed. */
const OAUTH_MODULES = [
    oauthEndpointsModule,
    oauthSessionGrantModule,
    oauthAuthorizationGrantsModule,
];
/** The modules the template composes that declare a renamed variable. */
const RENAMING_MODULES = [
    memoryRateLimiterModule,
    redisRateLimiterModule,
    redisRefreshTokenFamilyStoreModule,
    redisFederationGrantStoreModule,
    ...OAUTH_MODULES,
    sessionModule,
    sessionStoreModule,
    loggingModule,
    httpModule,
    keyStoreModule,
    standaloneRedisClientsModule,
    repositoriesModuleFor({ client: "yaml", user: "yaml" }),
    inMemoryCodeRepositoryModule,
];
/** Every package reference the template's modules declare, core's last. */
const LIBRARY_REFERENCES = moduleReferences([
    redisRateLimiterModule,
    ...federationGrantsModules,
    ...OAUTH_MODULES,
    sessionModule,
    sessionStoreModule,
]);
/** The libraries' references resolved under `env`, in the order `app.mts` layers them. */
export function libraryLayers(env) {
    return LIBRARY_REFERENCES.reduce((layered, reference) => layered.withFallback(parseFile(fileURLToPath(reference), { env: { ...env } })), empty());
}
/**
 * `switches` laid over `resolved`, the configuration boot parses, as a test
 * that hands one object to both phases does: the composition root's own keys
 * beside the sections, and `federation-grants.enabled` written as phase one
 * decided it into the section as resolved. Boot is so handed phase one's
 * boolean, not the value as written, unlike `app.mts`; boot's refusal of a
 * written value phase one installs the modules for is pinned in
 * `two-phase-config.test.mts`.
 */
export function withSwitches(resolved, switches) {
    const grants = resolved["federation-grants"];
    return {
        ...resolved,
        ...switches,
        "federation-grants": {
            ...(isPlainSection(grants) ? grants : {}),
            ...switches["federation-grants"],
        },
    };
}
/**
 * A resolution — `layers`, the template's `config/reference.conf` among them,
 * under `env` — as a test that resolves by hand hands it to both phases at
 * once: the configuration as resolved and unparsed, which boot parses as
 * `app.mts` hands it on, with what phase one reads of it (`readSwitches`)
 * laid over it — the composition root's `adapters` and `mfaMode`, the Store
 * transport settings, and `federation-grants.enabled` as phase one decides
 * it.
 */
export function bothPhasesOf(layers, env) {
    return withSwitches(layers.toObject(), readSwitches({ config: layers, env }));
}
/**
 * The composition root's `adapters` a resolution holds — `layers`, the
 * template's `config/reference.conf` among them, under `env` — as phase one
 * reads them.
 */
export function adaptersOf(layers, env) {
    return readAdapters(layers.toObject(), env);
}
/** The adapters the template ships, as its `config/reference.conf` sets them with no environment. */
export function shippedAdapters() {
    return adaptersOf(parseFile(fileURLToPath(templateReference()), { env: {} }), {});
}
/** The shipped adapters with every store the template can hold in process there: no Redis connection needed. */
export function inProcessAdapters() {
    return {
        ...shippedAdapters(),
        rateLimiter: "memory",
        userSessionStores: "memory",
        accessTokenDenylist: "memory",
        replaySeenSet: "memory",
        federationTokenStore: "memory",
        federationGrantStore: "memory",
        federationGrantIntentStore: "memory",
        mfaFactorStore: "memory",
        mfaTransactionStore: "memory",
        codeRepository: "memory",
    };
}
/**
 * The `renamed-variables` section a resolution under `env` holds: what every
 * module above captures, and the Redis code repository's, which the
 * in-process one's excludes from one composition (both declare
 * CLIENT_CODE_DEFAULT_EXPIRES_IN renamed, each to its own new name).
 */
export function capturedRenames(env) {
    return {
        ...renamedVariableCaptures({ modules: [redisCodeRepositoryModule], env }),
        ...renamedVariableCaptures({ modules: RENAMING_MODULES, core: CORE_RELOCATIONS, env }),
    };
}
