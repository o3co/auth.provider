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
	oauthAuthorizationModule,
	oauthModule,
	oauthSessionModule,
} from "@o3co/auth-provider-oauth";
import {
	redisFederationGrantStoreModule,
	redisRateLimiterModule,
	redisRefreshTokenFamilyStoreModule,
} from "@o3co/auth-provider-redis";
import { sessionModule, sessionStoreModule } from "@o3co/auth-provider-session";
import { type Config, empty, parseFile } from "@o3co/ts.hocon";
import {
	httpModule,
	keyStoreModule,
	loggingModule,
	standaloneRedisClientsModule,
} from "../modules.mjs";

/** The oauth package's modules, whose manifests read nothing of the configuration they are handed but the grant switches. */
const OAUTH_MODULES = [
	oauthModule({ config: {} as never }),
	oauthSessionModule({ config: {} as never }),
	oauthAuthorizationModule({ config: {} as never }),
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
 * template's own modules' among them — as written, which the parse drops.
 */
export function sectionsCoreDoesNotDeclare(layers: Config): Record<string, unknown> {
	const raw = layers.toObject() as Record<string, unknown>;
	return Object.fromEntries(
		Object.entries(raw).filter(
			([key]) => !Object.hasOwn(AppConfigSchema.shape, key) && key !== "renamed-variables",
		),
	);
}

/** The `renamed-variables` section a resolution under `env` holds. */
export function capturedRenames(
	env: Readonly<Record<string, string | undefined>>,
): Record<string, string | null> {
	return renamedVariableCaptures({ modules: RENAMING_MODULES, core: CORE_RELOCATIONS, env });
}
