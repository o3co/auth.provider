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

import type { FederationTokens } from "@o3co/auth-provider-core";
import { describe, expectTypeOf, it } from "vitest";
import type {
	FederationTokenCaller,
	FederationTokenContext,
} from "#/routes/federationTokenContext.mjs";
import { type DisclosableToken, isDisclosable } from "#/routes/federationTokenDisclosure.mjs";
import { answerToken } from "#/routes/federationTokenSuccess.mjs";

// The success answer always says `Bearer`, so the compiler holds every path
// to the disclosure check before it: a token reaches the answer only through it.
describe("the federation token success answer takes only a token judged disclosable", () => {
	it("refuses a record the disclosure check has not judged", () => {
		expectTypeOf<FederationTokens>().not.toExtend<Parameters<typeof answerToken>[2]>();

		const unjudged = (
			ctx: FederationTokenContext,
			caller: FederationTokenCaller,
			record: FederationTokens,
		) =>
			// @ts-expect-error the record has not been through the disclosure check
			answerToken(ctx, caller, record, false);
		expectTypeOf(unjudged).toBeFunction();
	});

	it("takes the record once the disclosure check has narrowed it", () => {
		expectTypeOf<Parameters<typeof answerToken>[2]>().toEqualTypeOf<DisclosableToken>();

		const judged = (
			ctx: FederationTokenContext,
			caller: FederationTokenCaller,
			record: FederationTokens,
		) => {
			if (!isDisclosable(record)) return undefined;
			expectTypeOf(record).toExtend<DisclosableToken>();
			return answerToken(ctx, caller, record, false);
		};
		expectTypeOf(judged).toBeFunction();
	});
});
