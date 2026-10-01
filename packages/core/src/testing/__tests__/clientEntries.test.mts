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
 * `clientEntries`, on the testing entry: client registrations written as a
 * registration file gives them, defaults left out, which
 * `InMemoryClientRepository` parses into its clients.
 */

import { describe, expect, it } from "vitest";
import { InMemoryClientRepository } from "#/repositories/InMemoryClientRepository.mjs";
import { clientEntries } from "#/testing/index.mjs";

describe("clientEntries", () => {
	it("hands InMemoryClientRepository entries without the schema's defaults, which it fills", async () => {
		const repo = new InMemoryClientRepository(
			clientEntries([
				[
					"rp",
					{
						tokenEndpointAuthMethod: "client_secret_basic",
						clientSecret: "s",
						allowedRedirectUris: [],
						allowedScopes: ["read"],
					},
				],
			]),
		);
		const client = await repo.findById("rp");
		expect(client?.clientId).toBe("rp");
		expect(client?.allowedScopes).toEqual(["read"]);
		expect(client?.tokenEndpointAuthMethod).toBe("client_secret_basic");
	});
});
