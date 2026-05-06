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
	type AdapterFactory,
	type BuilderContext,
	createAdapterFactory,
} from "../adapters/AdapterFactory.mjs";
import type { ClientRepository } from "./ClientRepository.mjs";
import type { CodeRepository } from "./CodeRepository.mjs";
import { ClientEntrySchema, InMemoryClientRepository } from "./InMemoryClientRepository.mjs";
import { InMemoryCodeRepository } from "./InMemoryCodeRepository.mjs";
import { InMemoryUserRepository, UserEntrySchema } from "./InMemoryUserRepository.mjs";
import { loadYamlMap } from "./loadYamlMap.mjs";
import type { UserRepository } from "./UserRepository.mjs";

/**
 * Construct the three default repository factories with built-in yaml/static/memory
 * adapters pre-registered. Consumers register additional adapters via:
 *   - `@o3co/auth-provider-foundation` `registerBuiltinAdapters` — http user repo
 *   - `@o3co/auth-provider-redis` builders (e.g. `redisCodeRepositoryBuilder`)
 *
 * @param ctx — optional `BuilderContext`. When supplied (typically from a
 *   module factory that received `deps.lifecycleRegistrar`), built-in
 *   builders that create disposable sub-resources (e.g. the memory
 *   `CodeRepository`'s GC interval) register their cleanup via
 *   `ctx.lifecycle?.register(...)` so `AppHandle.dispose()` drains them.
 *   Direct callers (unit tests, ad-hoc scripts) may omit `ctx`.
 */
export const createRepositoryFactories = (
	ctx?: BuilderContext,
): {
	clientFactory: AdapterFactory<ClientRepository>;
	userFactory: AdapterFactory<UserRepository>;
	codeFactory: AdapterFactory<CodeRepository>;
} => {
	const clientFactory = createAdapterFactory<ClientRepository>("ClientRepository", ctx ?? {});
	const yamlClientBuilder = (config: Record<string, unknown>): ClientRepository => {
		if (typeof config.path !== "string") {
			throw new Error('YAML client repository requires "path" in config');
		}
		return new InMemoryClientRepository(loadYamlMap(config.path, ClientEntrySchema));
	};
	clientFactory.register("yaml", yamlClientBuilder);
	clientFactory.register("static", yamlClientBuilder); // alias

	const userFactory = createAdapterFactory<UserRepository>("UserRepository", ctx ?? {});
	const yamlUserBuilder = (config: Record<string, unknown>): UserRepository => {
		if (typeof config.path !== "string") {
			throw new Error('YAML user repository requires "path" in config');
		}
		return new InMemoryUserRepository(loadYamlMap(config.path, UserEntrySchema));
	};
	userFactory.register("yaml", yamlUserBuilder);
	userFactory.register("static", yamlUserBuilder); // alias

	const codeFactory = createAdapterFactory<CodeRepository>("CodeRepository", ctx ?? {});
	codeFactory.register("memory", (config, builderCtx) => {
		const defaultExpiresIn =
			config.defaultExpiresIn != null ? Number(config.defaultExpiresIn) : undefined;
		if (
			defaultExpiresIn !== undefined &&
			(!Number.isFinite(defaultExpiresIn) || defaultExpiresIn <= 0)
		) {
			throw new Error('"defaultExpiresIn" must be a finite positive number');
		}
		const repo = new InMemoryCodeRepository({ defaultExpiresIn });
		// D-5 / IH-11: register the periodic-GC interval for disposal so it
		// doesn't keep the event loop alive past `AppHandle.dispose()`.
		builderCtx.lifecycle?.register(async () => {
			repo.dispose();
		});
		return repo;
	});

	return { clientFactory, userFactory, codeFactory };
};
