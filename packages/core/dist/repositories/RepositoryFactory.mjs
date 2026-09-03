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
import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { ClientEntrySchema, InMemoryClientRepository } from "./InMemoryClientRepository.mjs";
import { InMemoryCodeRepository } from "./InMemoryCodeRepository.mjs";
import { InMemoryUserRepository, UserEntrySchema } from "./InMemoryUserRepository.mjs";
import { loadYamlMap } from "./loadYamlMap.mjs";
/**
 * Construct the three default repository factories with built-in yaml/static/memory
 * adapters pre-registered. Consumers register additional adapters (e.g. http, redis)
 * via `registerBuiltinAdapters` from `@o3co/auth-provider-foundation`.
 */
export const createDefaultFactories = () => {
    const clientFactory = createAdapterFactory("ClientRepository");
    const yamlClientBuilder = (config) => {
        if (typeof config.path !== "string") {
            throw new Error('YAML client repository requires "path" in config');
        }
        return new InMemoryClientRepository(loadYamlMap(config.path, ClientEntrySchema));
    };
    clientFactory.register("yaml", yamlClientBuilder);
    clientFactory.register("static", yamlClientBuilder); // alias
    const userFactory = createAdapterFactory("UserRepository");
    const yamlUserBuilder = (config) => {
        if (typeof config.path !== "string") {
            throw new Error('YAML user repository requires "path" in config');
        }
        return new InMemoryUserRepository(loadYamlMap(config.path, UserEntrySchema));
    };
    userFactory.register("yaml", yamlUserBuilder);
    userFactory.register("static", yamlUserBuilder); // alias
    const codeFactory = createAdapterFactory("CodeRepository");
    codeFactory.register("memory", (config) => {
        const defaultExpiresIn = config.defaultExpiresIn != null ? Number(config.defaultExpiresIn) : undefined;
        if (defaultExpiresIn !== undefined &&
            (!Number.isFinite(defaultExpiresIn) || defaultExpiresIn <= 0)) {
            throw new Error('"defaultExpiresIn" must be a finite positive number');
        }
        return new InMemoryCodeRepository({ defaultExpiresIn });
    });
    return { clientFactory, userFactory, codeFactory };
};
