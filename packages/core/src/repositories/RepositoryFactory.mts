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

import type { ClientRepository } from "./ClientRepository.mjs";
import type { CodeRepository } from "./CodeRepository.mjs";
import { ClientEntrySchema, InMemoryClientRepository } from "./InMemoryClientRepository.mjs";
import { InMemoryCodeRepository } from "./InMemoryCodeRepository.mjs";
import { InMemoryUserRepository, UserEntrySchema } from "./InMemoryUserRepository.mjs";
import { loadYamlMap } from "./loadYamlMap.mjs";
import type { UserRepository } from "./UserRepository.mjs";

export type RepositoryBuilder<T> = (config: Record<string, unknown>) => Promise<T> | T;

export class RepositoryFactory<T> {
	private builders = new Map<string, RepositoryBuilder<T>>();
	private readonly label: string;

	constructor(label: string) {
		this.label = label;
	}

	register(type: string, builder: RepositoryBuilder<T>): void {
		this.builders.set(type, builder);
	}

	async create(config: { type: string; [key: string]: unknown }): Promise<T> {
		const builder = this.builders.get(config.type);
		if (!builder) {
			const registered = [...this.builders.keys()];
			const suffix =
				registered.length > 0
					? `Registered types: ${registered.join(", ")}`
					: "No types registered";
			throw new Error(`Unknown ${this.label} repository type: "${config.type}". ${suffix}`);
		}
		return builder(config);
	}
}

export const createDefaultFactories = (): {
	clientFactory: RepositoryFactory<ClientRepository>;
	userFactory: RepositoryFactory<UserRepository>;
	codeFactory: RepositoryFactory<CodeRepository>;
} => {
	const clientFactory = new RepositoryFactory<ClientRepository>("client");
	const yamlClientBuilder: RepositoryBuilder<ClientRepository> = (config) => {
		if (typeof config.path !== "string") {
			throw new Error('YAML client repository requires "path" in config');
		}
		return new InMemoryClientRepository(loadYamlMap(config.path, ClientEntrySchema));
	};
	clientFactory.register("yaml", yamlClientBuilder);
	clientFactory.register("static", yamlClientBuilder); // backward compat alias

	const userFactory = new RepositoryFactory<UserRepository>("user");
	const yamlUserBuilder: RepositoryBuilder<UserRepository> = (config) => {
		if (typeof config.path !== "string") {
			throw new Error('YAML user repository requires "path" in config');
		}
		return new InMemoryUserRepository(loadYamlMap(config.path, UserEntrySchema));
	};
	userFactory.register("yaml", yamlUserBuilder);
	userFactory.register("static", yamlUserBuilder); // backward compat alias

	const codeFactory = new RepositoryFactory<CodeRepository>("code");
	codeFactory.register("memory", (config) => {
		const defaultExpiresIn =
			config.defaultExpiresIn != null ? Number(config.defaultExpiresIn) : undefined;
		if (
			defaultExpiresIn !== undefined &&
			(!Number.isFinite(defaultExpiresIn) || defaultExpiresIn <= 0)
		) {
			throw new Error('"defaultExpiresIn" must be a finite positive number');
		}
		return new InMemoryCodeRepository({ defaultExpiresIn });
	});

	return { clientFactory, userFactory, codeFactory };
};
