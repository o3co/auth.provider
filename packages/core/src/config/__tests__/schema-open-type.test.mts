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
import { fullSectionsSchema } from "#/config/application.schema.mjs";

describe("schema open type", () => {
	it("accepts non-builtin session storage type (validated at factory level, not schema)", () => {
		const parsed = fullSectionsSchema.shape.session.parse({
			secret: "s",
			storage: {
				type: "memcached",
				redis: { url: "redis://localhost:6379" },
			},
		});
		expect(parsed.storage.type).toBe("memcached");
	});

	it("still accepts the builtin session storage types", () => {
		for (const type of ["redis", "memory"]) {
			const parsed = fullSectionsSchema.shape.session.parse({
				secret: "s",
				storage: {
					type,
					redis: { url: "redis://localhost:6379" },
				},
			});
			expect(parsed.storage.type).toBe(type);
		}
	});

	it("accepts non-builtin clients.client.type (flat shape — nested migration comes in Task 3)", () => {
		const parsed = fullSectionsSchema.shape.clients.parse({
			client: { type: "postgres", path: "./config/clients.yaml" },
			user: { type: "yaml", path: "./config/users.yaml" },
			code: { type: "memory" },
		});
		expect(parsed.client.type).toBe("postgres");
	});

	it("accepts non-builtin clients.user.type and clients.code.type", () => {
		const parsed = fullSectionsSchema.shape.clients.parse({
			client: { type: "yaml", path: "./clients.yaml" },
			user: { type: "ldap", path: "./users.yaml" },
			code: { type: "dynamodb" },
		});
		expect(parsed.user.type).toBe("ldap");
		expect(parsed.code.type).toBe("dynamodb");
	});
});
