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
 * The contract suite of the `httpSettings` slot.
 * `httpSettingsContract(input)` holds the settings to the configuration
 * schema's rules: a `trustProxy` Express reads as meant (a boolean, a hop
 * count up to `MAX_TRUST_PROXY_HOPS`, or a non-empty list of entries
 * `checkTrustedProxyEntry` accepts), CORS origins `checkSerializedOrigin`
 * accepts, the whole frozen. The slot's test double,
 * `createTestHttpSettings`, is core's, on its testing entry.
 */

import assert from "node:assert/strict";
import {
	checkSerializedOrigin,
	checkTrustedProxyEntry,
	describeSerializedOriginRejection,
	describeTrustedProxyEntryRejection,
	type HttpSettings,
	MAX_TRUST_PROXY_HOPS,
} from "@o3co/auth-provider-core";
import type { ContractCase } from "@o3co/auth-provider-core/testing";
import { unfrozenPath } from "../unfrozenPath.mjs";

export interface HttpSettingsContractInput {
	/** The settings under test, built afresh for each case: a provider's, over the configuration its test chose. */
	readonly build: () => HttpSettings;
}

/** The cases of the `httpSettings` contract over the settings `input` builds. */
export function httpSettingsContract(input: HttpSettingsContractInput): readonly ContractCase[] {
	const { build } = input;
	return [
		{
			name: "trustProxy is what Express's trust proxy takes: true or false, a hop count from 0 to 255, or a non-empty list of addresses, ranges and named ranges",
			run: async () => {
				const { trustProxy } = build();
				if (typeof trustProxy === "boolean") return;
				if (typeof trustProxy === "number") {
					assert.ok(
						Number.isInteger(trustProxy) && trustProxy >= 0 && trustProxy <= MAX_TRUST_PROXY_HOPS,
						`trustProxy ${trustProxy} is not a hop count from 0 to ${MAX_TRUST_PROXY_HOPS}`,
					);
					return;
				}
				assert.ok(
					Array.isArray(trustProxy) && trustProxy.length > 0,
					`trustProxy ${JSON.stringify(trustProxy)} is neither a boolean, a hop count nor a non-empty list`,
				);
				trustProxy.forEach((entry, index) => {
					const rejection = checkTrustedProxyEntry(entry);
					assert.equal(
						rejection,
						null,
						rejection === null
							? ""
							: `trustProxy[${index}] ${describeTrustedProxyEntryRejection(rejection)}`,
					);
				});
			},
		},
		{
			name: "cors.allowedOrigins lists serialized origins: a scheme, a host and a port that is not the scheme's default",
			run: async () => {
				const origins = build().cors?.allowedOrigins;
				assert.ok(Array.isArray(origins), "cors.allowedOrigins is not a list");
				origins.forEach((origin, index) => {
					const rejection =
						typeof origin === "string" ? checkSerializedOrigin(origin) : "not a string";
					assert.equal(
						rejection,
						null,
						rejection === null
							? ""
							: `cors.allowedOrigins[${index}] ${
									typeof rejection === "string" && rejection === "not a string"
										? "is not a string"
										: describeSerializedOriginRejection(rejection)
								}`,
					);
				});
			},
		},
		{
			name: "the settings are frozen, the lists too",
			run: async () => {
				const found = unfrozenPath(build(), "the settings");
				assert.equal(
					found,
					undefined,
					`${found} is not frozen: a module that reads the settings could change them under the others`,
				);
			},
		},
	];
}
