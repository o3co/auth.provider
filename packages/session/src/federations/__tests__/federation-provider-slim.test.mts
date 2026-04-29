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
import { expectTypeOf, test } from "vitest";
import type { FederationProvider } from "../types.mjs";

test("FederationProvider has buildAuthorizationUrl", () => {
	expectTypeOf<FederationProvider>().toHaveProperty("buildAuthorizationUrl");
});

test("FederationProvider has exchangeCode", () => {
	expectTypeOf<FederationProvider>().toHaveProperty("exchangeCode");
});

test("FederationProvider has name and scope", () => {
	expectTypeOf<FederationProvider>().toHaveProperty("name");
	expectTypeOf<FederationProvider>().toHaveProperty("scope");
});

test("FederationProvider does NOT have validateRedirect (removed in A5)", () => {
	type HasValidateRedirect = "validateRedirect" extends keyof FederationProvider ? true : false;
	expectTypeOf<HasValidateRedirect>().toEqualTypeOf<false>();
});

test("FederationProvider does NOT have resolveCallbackRedirect (removed in A5)", () => {
	type HasResolve = "resolveCallbackRedirect" extends keyof FederationProvider ? true : false;
	expectTypeOf<HasResolve>().toEqualTypeOf<false>();
});
