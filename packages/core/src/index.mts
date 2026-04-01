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

// Repository interfaces and types
export type { Client, User, Code, CodeData } from "./repositories/types.mjs";
export type { ClientRepository, PublicClient } from "./repositories/ClientRepository.mjs";
export type { UserRepository } from "./repositories/UserRepository.mjs";
export type { CodeRepository } from "./repositories/CodeRepository.mjs";

// Built-in implementation
export { StaticClientRepository } from "./repositories/StaticClientRepository.mjs";

// Grant types
export type {
	GrantDependencies,
	GrantContext,
	GrantHandler,
	GrantFactory,
} from "./routes/grants/types.mjs";
export { GrantRegistry } from "./routes/grants/registry.mjs";

// Router and Passport factories
export { createRouter } from "./routes/index.mjs";
export { createPassport } from "./Passport.mjs";

// Configuration
export { AppConfigSchema, type AppConfig } from "./config/application.schema.mjs";
