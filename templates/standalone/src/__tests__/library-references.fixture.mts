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
 * and what that resolution captures of the renamed variables.
 */

import { fileURLToPath } from "node:url";
import {
	AppConfigSchema,
	memoryRateLimiterModule,
	moduleReferences,
} from "@o3co/auth-provider-core";
import { CORE_RELOCATIONS, renamedVariableCaptures } from "@o3co/auth-provider-core/testing";
import { federationGrantsModules } from "@o3co/auth-provider-federation-grants";
import {
	oauthAuthorizationGrantsModule,
	oauthModule,
	oauthSessionGrantModule,
} from "@o3co/auth-provider-oauth";
import {
	redisCodeRepositoryModule,
	redisFederationGrantStoreModule,
	redisRateLimiterModule,
	redisRefreshTokenFamilyStoreModule,
} from "@o3co/auth-provider-redis";
import { sessionModule, sessionStoreModule } from "@o3co/auth-provider-session";
import { type Config, empty, parseFile } from "@o3co/ts.hocon";
import { ADAPTERS_SECTION, readAdapters } from "../adapters.mjs";
import { MFA_SWITCH, readMfaSwitch } from "../mfaSwitch.mjs";
import {
	httpModule,
	inMemoryCodeRepositoryModule,
	keyStoreModule,
	loggingModule,
	repositoriesModuleFor,
	standaloneRedisClientsModule,
	templateReference,
} from "../modules.mjs";
import type { Adapters, MfaSwitch } from "../sections.mjs";

/** The oauth package's modules: none reads the configuration it is handed. */
const OAUTH_MODULES = [
	oauthModule({ config: {} as never }),
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
const LIBRARY_REFERENCES: readonly URL[] = moduleReferences([
	redisRateLimiterModule,
	...federationGrantsModules,
	...OAUTH_MODULES,
	sessionModule,
	sessionStoreModule,
]);

/** The libraries' references resolved under `env`, in the order `app.mts` layers them. */
export function libraryLayers(env: Readonly<Record<string, string>>): Config {
	return LIBRARY_REFERENCES.reduce<Config>(
		(layered, reference) =>
			layered.withFallback(parseFile(fileURLToPath(reference), { env: { ...env } })),
		empty(),
	);
}

/**
 * What a test that parses `layers` with `AppConfigSchema` lays beside that
 * parse: every top-level section core's schema does not declare — the
 * template's own modules' among them — as written, which the parse drops;
 * not the composition root's `adapters`, which boot is never handed
 * (`adaptersOf`).
 */
export function sectionsCoreDoesNotDeclare(layers: Config): Record<string, unknown> {
	const raw = layers.toObject() as Record<string, unknown>;
	return Object.fromEntries(
		Object.entries(raw).filter(
			([key]) =>
				!Object.hasOwn(AppConfigSchema.shape, key) &&
				key !== "renamed-variables" &&
				key !== ADAPTERS_SECTION &&
				key !== MFA_SWITCH,
		),
	);
}

/**
 * The composition root's `adapters` a resolution holds — `layers`, the
 * template's `config/reference.conf` among them, under `env` — as phase one
 * reads them.
 */
export function adaptersOf(layers: Config, env: Readonly<Record<string, string>>): Adapters {
	return readAdapters(layers.toObject() as Record<string, unknown>, env);
}

/**
 * What phase one reads from a resolution beside core's switches —
 * `layers`, the template's `config/reference.conf` among them, under `env` —
 * as `readSwitches` reads it: the composition root's `adapters` and
 * `mfaMode`, and the Store transport settings.
 */
export function rootSectionsOf(
	layers: Config,
	env: Readonly<Record<string, string>>,
): { readonly adapters: Adapters; readonly mfaMode: MfaSwitch; readonly storeTransport: unknown } {
	const raw = layers.toObject() as Record<string, unknown>;
	const repositories = raw.repositories as { user?: { http?: unknown } } | undefined;
	return {
		adapters: readAdapters(raw, env),
		mfaMode: readMfaSwitch(raw, env),
		storeTransport: repositories?.user?.http,
	};
}

/** The adapters the template ships, as its `config/reference.conf` sets them with no environment. */
export function shippedAdapters(): Adapters {
	return adaptersOf(parseFile(fileURLToPath(templateReference()), { env: {} }), {});
}

/** The shipped adapters with every store the template can hold in process there: no Redis connection needed. */
export function inProcessAdapters(): Adapters {
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
export function capturedRenames(
	env: Readonly<Record<string, string | undefined>>,
): Record<string, string | null> {
	return {
		...renamedVariableCaptures({ modules: [redisCodeRepositoryModule], env }),
		...renamedVariableCaptures({ modules: RENAMING_MODULES, core: CORE_RELOCATIONS, env }),
	};
}
