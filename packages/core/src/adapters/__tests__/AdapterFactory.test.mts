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
import { AdapterFactoryError } from "#/adapters/AdapterFactory.mjs";

describe("AdapterFactoryError", () => {
	it("formats the message with kind, requested type, and registered types", () => {
		const err = new AdapterFactoryError({
			kind: "UserRepository",
			type: "postgres",
			registered: ["yaml", "http"],
		});

		expect(err).toBeInstanceOf(Error);
		expect(err.name).toBe("AdapterFactoryError");
		expect(err.message).toBe(
			'AdapterFactoryError [UserRepository]: unknown type "postgres". Registered types: yaml, http',
		);
		expect(err.kind).toBe("UserRepository");
		expect(err.type).toBe("postgres");
		expect(err.registered).toEqual(["yaml", "http"]);
	});

	it("handles empty registered list", () => {
		const err = new AdapterFactoryError({
			kind: "SessionStore",
			type: "memcached",
			registered: [],
		});

		expect(err.message).toBe(
			'AdapterFactoryError [SessionStore]: unknown type "memcached". No types registered',
		);
	});
});
