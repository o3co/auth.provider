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
	BootErrorDetails,
	BootErrorReason,
	FederationRedirectPolicyUnpairedDetails,
} from "../types.mjs";

test("BootErrorReason includes federation-redirect-policy-unpaired", () => {
	// Verify the literal is a valid member of the union (assignability check).
	const r: BootErrorReason = "federation-redirect-policy-unpaired";
	expectTypeOf(r).toMatchTypeOf<BootErrorReason>();
});

test("FederationRedirectPolicyUnpairedDetails has the correct shape", () => {
	expectTypeOf<FederationRedirectPolicyUnpairedDetails>().toEqualTypeOf<{
		readonly reason: "federation-redirect-policy-unpaired";
		readonly name: string;
		readonly side: "federation-without-policy" | "policy-without-federation";
		readonly contributedBy: string;
	}>();
});

test("BootErrorDetails union includes FederationRedirectPolicyUnpairedDetails", () => {
	type Unpaired = Extract<BootErrorDetails, { reason: "federation-redirect-policy-unpaired" }>;
	expectTypeOf<Unpaired>().toEqualTypeOf<FederationRedirectPolicyUnpairedDetails>();
});
