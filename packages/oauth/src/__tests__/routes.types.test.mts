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

import type { GrantHandlerResolver } from "@o3co/auth-provider-core";
import type { GrantRegistry } from "@o3co/auth-provider-core/testing";
import { describe, expect, expectTypeOf, it } from "vitest";
import type { createOAuthRouter } from "#/routes.mjs";

// #626 (comment): `createOAuthRouter` reads `registry.get` and nothing else
// (`module.mts` reads `entries()` off the planner's resolver, not off the
// router's), so its `registry` parameter asks for `get` alone — whatever
// else a registry has. It once asked for the whole `GrantHandlerResolver`,
// which core's `GrantRegistry` could not satisfy while it had no `entries`,
// and that kept 27 of this package's test files out of typecheck. The
// contract is what the router reads; these fire under typecheck only.

type RouterOptions = Parameters<typeof createOAuthRouter>[1];
type RouterResult = Awaited<ReturnType<typeof createOAuthRouter>>;

describe("createOAuthRouter's registry contract is what it reads (#626)", () => {
	it("asks for `get` only", () => {
		expectTypeOf<RouterOptions["registry"]>().toEqualTypeOf<Pick<GrantHandlerResolver, "get">>();
		expectTypeOf<RouterOptions["registry"]>().not.toHaveProperty("entries");
		expect(true).toBe(true);
	});

	it("is satisfied by core's test GrantRegistry, which a test hands it directly", () => {
		expectTypeOf<GrantRegistry>().toMatchTypeOf<RouterOptions["registry"]>();
		// And by the planner's resolver, which the bundled module hands it.
		expectTypeOf<GrantHandlerResolver>().toMatchTypeOf<RouterOptions["registry"]>();
		expect(true).toBe(true);
	});

	it("returns the registry it was given, at the same contract", () => {
		expectTypeOf<RouterResult["registry"]>().toEqualTypeOf<Pick<GrantHandlerResolver, "get">>();
		expect(true).toBe(true);
	});
});
