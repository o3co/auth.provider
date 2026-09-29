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
	type AppHandle,
	type BootstrapMap,
	type CreateAppOptions,
	createApp,
	type DefaultBootstrapMap,
} from "../boot/index.mjs";
import { makeValidAppConfig } from "./fixtures/valid-config.mjs";
import type { TestInspect } from "./test-inspect.mjs";

export type { TestInspect } from "./test-inspect.mjs";

export type TestAppHandle = AppHandle & { readonly inspect: TestInspect };

/**
 * `createApp` for tests, with:
 * 1. Synthesised bootstrap components when `bootstrapComponents` is omitted —
 *    a minimal `{ config, pathResolver }` sufficient for a smoke-test boot.
 *    When `bootstrapComponents` is supplied, it is used verbatim — NO MERGE.
 * 2. A read-only `inspect` view of the registries on the returned handle:
 *    a testing-only escape hatch that MUST NOT appear on the production
 *    AppHandle.
 */
export async function createTestApp<B extends BootstrapMap = DefaultBootstrapMap>(
	options?: Partial<CreateAppOptions<B>>,
): Promise<TestAppHandle> {
	const bootstrapComponents =
		options?.bootstrapComponents ??
		({ config: makeValidAppConfig(), pathResolver: (s: string) => s } as unknown as B);

	const handle = await createApp<B>({
		modules: options?.modules ?? [],
		bootstrapComponents,
		overrideComponents: options?.overrideComponents,
		contributionKinds: options?.contributionKinds,
	} as CreateAppOptions<B>);

	const inspect: TestInspect = projectInspect(handle);

	// AppHandle is frozen by assembleApp: spread into a new plain object so
	// the testing-only `inspect` field does not touch the production handle.
	return { ...handle, inspect } as TestAppHandle;
}

function projectInspect(handle: AppHandle): TestInspect {
	// The planner's synthetic collectors as ReadonlyMap views: the two
	// resolvers expose `.entries()`; `federationProviders` is already a map.
	const { grantHandlerResolver, tokenExchangeValidatorResolver, federationProviders } =
		handle.components;

	const grants = new Map(grantHandlerResolver?.entries() ?? []);
	const federations = new Map(federationProviders?.entries() ?? []);
	const tokenExchangeValidators = new Map(tokenExchangeValidatorResolver?.entries() ?? []);
	const routes = handle.routes;

	return Object.freeze({ grants, federations, tokenExchangeValidators, routes });
}
