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

/**
 * `HttpMfaFactorStore` held to the test kit's `MfaFactorStore` contract
 * suite, over the kit's fake Store: a fresh Store and a fresh version floor
 * for each case, every request carrying the bearer token the Store requires.
 */

import { createMemoryReplaySeenSet } from "@o3co/auth-provider-core";
import { mfaFactorStoreContract, startFakeStore } from "@o3co/auth-provider-test-kit";
import { describe, it } from "vitest";
import { HttpMfaFactorStore } from "#/index.mjs";

const TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

describe("HttpMfaFactorStore over the fake Store", () => {
	for (const contractCase of mfaFactorStoreContract({
		build: async () => {
			const fake = await startFakeStore({ bearerToken: TOKEN });
			const store = new HttpMfaFactorStore({
				listUrl: fake.urls.listUrl,
				createUrl: fake.urls.createUrl,
				updateUrl: fake.urls.updateUrl,
				deleteUrl: fake.urls.deleteUrl,
				bearerToken: TOKEN,
				timeout: 5000,
				replaySeenSet: createMemoryReplaySeenSet(),
			});
			return { store, close: () => fake.close() };
		},
	})) {
		it(contractCase.name, contractCase.run);
	}
});
