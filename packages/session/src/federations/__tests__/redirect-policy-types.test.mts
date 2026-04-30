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
import type {
	FederationRedirectPolicy,
	FederationRedirectPolicyFactory,
} from "../redirect-policy.mjs";
import type { FederationResult } from "../types.mjs";

test("FederationResult ok-true variant has readonly fields", () => {
	type OkVariant = Extract<FederationResult<string>, { ok: true }>;
	expectTypeOf<OkVariant>().toEqualTypeOf<{
		readonly ok: true;
		readonly value: string;
	}>();
});

test("FederationResult ok-false variant has readonly fields", () => {
	type ErrVariant = Extract<FederationResult<string>, { ok: false }>;
	expectTypeOf<ErrVariant>().toEqualTypeOf<{
		readonly ok: false;
		readonly status: number;
		readonly error: string;
		readonly errorDescription: string;
	}>();
});

test("FederationRedirectPolicy exposes validateRedirect and resolveCallbackRedirect", () => {
	expectTypeOf<FederationRedirectPolicy>().toHaveProperty("validateRedirect");
	expectTypeOf<FederationRedirectPolicy>().toHaveProperty("resolveCallbackRedirect");
	expectTypeOf<FederationRedirectPolicy["validateRedirect"]>().toBeFunction();
	expectTypeOf<FederationRedirectPolicy["resolveCallbackRedirect"]>().toBeFunction();
});

test("FederationRedirectPolicy.validateRedirect returns FederationResult<void>", () => {
	type Ret = ReturnType<FederationRedirectPolicy["validateRedirect"]>;
	expectTypeOf<Ret>().toEqualTypeOf<FederationResult<void>>();
});

test("FederationRedirectPolicy.resolveCallbackRedirect returns FederationResult<string>", () => {
	type Ret = ReturnType<FederationRedirectPolicy["resolveCallbackRedirect"]>;
	expectTypeOf<Ret>().toEqualTypeOf<FederationResult<string>>();
});

test("FederationRedirectPolicyFactory is a function type", () => {
	// biome-ignore lint/suspicious/noExplicitAny: testing generic factory shape
	expectTypeOf<FederationRedirectPolicyFactory<any>>().toBeFunction();
});
