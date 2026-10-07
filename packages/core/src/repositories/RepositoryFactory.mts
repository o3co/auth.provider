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
	type AdapterBuilder,
	type AdapterFactory,
	type BuilderContext,
	createAdapterFactory,
} from "../adapters/AdapterFactory.mjs";
import { wholeNumberInRangeFromEnv } from "../config/application.schema.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { ClientRepository } from "./ClientRepository.mjs";
import type { CodeRepository } from "./CodeRepository.mjs";
import { ClientEntrySchema, InMemoryClientRepository } from "./InMemoryClientRepository.mjs";
import { InMemoryCodeRepository } from "./InMemoryCodeRepository.mjs";
import { InMemoryUserRepository, UserEntrySchema } from "./InMemoryUserRepository.mjs";
import { loadYamlMap } from "./loadYamlMap.mjs";
import type { UserRepository } from "./UserRepository.mjs";

/** The memory code repository's `defaultExpiresIn`: a positive whole number of seconds. */
const positiveWholeNumber = wholeNumberInRangeFromEnv(1);

/**
 * Construct the three default repository factories with the built-in
 * yaml/static/memory adapters registered. Other packages add their own
 * (`@o3co/auth-provider-foundation` `registerBuiltinAdapters`, the
 * `@o3co/auth-provider-redis` builders).
 *
 * @param ctx — optional `BuilderContext`. When supplied, builders that own
 *   disposable resources (e.g. the memory `CodeRepository`'s GC interval)
 *   register their cleanup so `AppHandle.dispose()` drains them.
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
	/**
	 * The users file is meant for development and tests: a deployment's users
	 * are its Store's. Each repository built says so once, object-first, at
	 * warn, as `user_repository_in_memory` with the name it was built under.
	 * It warns wherever it runs, whatever the environment, as the in-memory
	 * MFA factor store does.
	 */
	const yamlUserBuilder =
		(adapter: "yaml" | "static"): AdapterBuilder<UserRepository> =>
		(config, builderCtx) => {
			if (typeof config.path !== "string") {
				throw new Error('YAML user repository requires "path" in config');
			}
			const repository = new InMemoryUserRepository(loadYamlMap(config.path, UserEntrySchema));
			(builderCtx.logger ?? consoleLogger).warn(
				{ store: "userRepository", adapter },
				"user_repository_in_memory",
			);
			return repository;
		};
	userFactory.register("yaml", yamlUserBuilder("yaml"));
	userFactory.register("static", yamlUserBuilder("static")); // alias

	const codeFactory = createAdapterFactory<CodeRepository>("CodeRepository", ctx ?? {});
	codeFactory.register("memory", (config, builderCtx) => {
		// Whole seconds in decimal digits, as the Redis repository's module schema
		// requires. A RangeError, as the repository's own constructor refuses the same.
		const read =
			config.defaultExpiresIn !== undefined
				? positiveWholeNumber.safeParse(config.defaultExpiresIn)
				: undefined;
		if (read !== undefined && !read.success) {
			throw new RangeError(
				'"defaultExpiresIn" must be a positive whole number of seconds, in decimal digits',
			);
		}
		const defaultExpiresIn = read?.data;
		const repo = new InMemoryCodeRepository({ defaultExpiresIn });
		// Register the periodic-GC interval for disposal so it doesn't keep the
		// event loop alive past `AppHandle.dispose()`.
		builderCtx.lifecycle?.register(async () => {
			repo.dispose();
		});
		return repo;
	});

	return { clientFactory, userFactory, codeFactory };
};
