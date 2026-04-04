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
import type { Router } from "express";

import type { AppConfig } from "#/config/application.schema.mjs";
import type { GrantRegistry } from "#/grants/registry.mjs";
import type { KeyStore } from "#/keys/KeyStore.mjs";

/**
 * Resolves a module specifier to a URL/path that can be passed to dynamic import().
 * Typically set to import.meta.resolve at the application level.
 */
export type PathResolver = (specifier: string) => string;

/**
 * Context provided to each Module during initialization.
 */
export interface ModuleContext {
	pathResolver: PathResolver;
	config: AppConfig;
	keyStore: KeyStore;
	grantRegistry: GrantRegistry;
	router: Router;
}

/**
 * A composable unit that registers routes and/or grant handlers.
 * Modules are initialized asynchronously to allow dynamic imports via pathResolver.
 */
export interface Module {
	name: string;
	init(context: ModuleContext): Promise<void>;
}
