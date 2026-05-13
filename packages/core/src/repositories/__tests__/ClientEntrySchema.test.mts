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
import { describe, expect, it } from "vitest";
import { ClientEntrySchema } from "#/repositories/InMemoryClientRepository.mjs";

describe("ClientEntrySchema — allowedGrantTypes field (Wave 1 §3.4.1)", () => {
	it("accepts absent allowedGrantTypes (existing clients)", () => {
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
		});
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.allowedGrantTypes).toBeUndefined();
	});

	it("accepts allowedGrantTypes as string array", () => {
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
			allowedGrantTypes: ["authorization_code", "refresh_token", "client_credentials"],
		});
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.allowedGrantTypes).toEqual([
				"authorization_code",
				"refresh_token",
				"client_credentials",
			]);
		}
	});

	it("accepts empty allowedGrantTypes array", () => {
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
			allowedGrantTypes: [],
		});
		expect(result.success).toBe(true);
	});

	it("rejects non-string values in allowedGrantTypes", () => {
		const result = ClientEntrySchema.safeParse({
			tokenEndpointAuthMethod: "client_secret_basic",
			clientSecret: "s",
			allowedGrantTypes: ["client_credentials", 42],
		});
		expect(result.success).toBe(false);
	});
});
