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
 * suite and to the factor set's conditional-write binding, over the kit's
 * fake Store: a fresh Store for each case, every request carrying the bearer
 * token the Store requires. The second instance is another adapter on the
 * same Store, the unreachable one an adapter whose Store has closed, and
 * `forceExpire` moves the Store's tombstone clock on by the write-lifetime
 * bound, leaving the clock a write's deadline is checked against.
 */

import { BUNDLED_STORE_WRITE_LIFETIME_MS } from "@o3co/auth-provider-core";
import {
	type FakeStoreUrls,
	type MfaFactorStoreContractInput,
	mfaFactorStoreConditionalContract,
	mfaFactorStoreContract,
	startFakeStore,
} from "@o3co/auth-provider-test-kit";
import { describe, it } from "vitest";
import { HttpMfaFactorStore } from "#/index.mjs";

const TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/** Each of the set's cases may take this long: its races make many requests over HTTP. */
const SET_CASE_TIMEOUT_MS = 60_000;

const adapterOver = (urls: FakeStoreUrls): HttpMfaFactorStore =>
	new HttpMfaFactorStore({
		listUrl: urls.listUrl,
		createUrl: urls.createUrl,
		updateUrl: urls.updateUrl,
		deleteUrl: urls.deleteUrl,
		bearerToken: TOKEN,
		timeout: 5000,
	});

const input: MfaFactorStoreContractInput = {
	build: async () => {
		let aheadMs = 0;
		const fake = await startFakeStore({ bearerToken: TOKEN, now: () => Date.now() + aheadMs });
		const closed = await startFakeStore({ bearerToken: TOKEN });
		await closed.close();
		return {
			store: adapterOver(fake.urls),
			second: adapterOver(fake.urls),
			unreachable: () => adapterOver(closed.urls),
			forceExpire: async () => {
				aheadMs += BUNDLED_STORE_WRITE_LIFETIME_MS;
			},
			close: () => fake.close(),
		};
	},
	supports: { unreachable: true, forceExpire: true },
};

describe("HttpMfaFactorStore over the fake Store", () => {
	for (const contractCase of mfaFactorStoreContract(input)) {
		it(contractCase.name, contractCase.run);
	}
});

describe("HttpMfaFactorStore's factor set over the fake Store", () => {
	for (const contractCase of mfaFactorStoreConditionalContract(input)) {
		it(contractCase.name, contractCase.run, SET_CASE_TIMEOUT_MS);
	}
});
