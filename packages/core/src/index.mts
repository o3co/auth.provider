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

// Configuration
export { type AppConfig, AppConfigSchema } from "./config/application.schema.mjs";
// Grant registry and types
export { GrantRegistry } from "./grants/registry.mjs";
export type {
	GrantContext,
	GrantDependencies,
	GrantFactory,
	GrantHandler,
} from "./grants/types.mjs";
export { createPassport } from "./Passport.mjs";
// Repository interfaces
export type { ClientRepository, PublicClient } from "./repositories/ClientRepository.mjs";
export type { CodeRepository } from "./repositories/CodeRepository.mjs";
// Built-in implementations
export { StaticClientRepository } from "./repositories/StaticClientRepository.mjs";
export type { Client, Code, CodeData, User } from "./repositories/types.mjs";
export type { UserRepository } from "./repositories/UserRepository.mjs";
// Router factory
export { createRouter } from "./routes/index.mjs";
