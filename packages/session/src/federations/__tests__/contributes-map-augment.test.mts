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
import type { ComponentMap, ContributesMap } from "@o3co/auth-provider-core";
import { expectTypeOf, test } from "vitest";
// Side-effect import: ensure the declaration-merge augmentations are loaded
import "../contributes.mjs";
import type { FederationRedirectPolicy } from "../redirect-policy.mjs";

test("ContributesMap has federationRedirectPolicies optional slot", () => {
	type Slot = ContributesMap["federationRedirectPolicies"];
	const _check: Slot = {
		google: () => ({
			validateRedirect: () => ({ ok: true, value: undefined }),
			resolveCallbackRedirect: () => ({ ok: true, value: "" }),
		}),
	};
	expectTypeOf<Slot>().not.toBeNever();
	void _check;
});

test("ComponentMap has federationRedirectPolicyResolver optional slot", () => {
	type Slot = ComponentMap["federationRedirectPolicyResolver"];
	expectTypeOf<NonNullable<Slot>>().toMatchTypeOf<ReadonlyMap<string, FederationRedirectPolicy>>();
});
