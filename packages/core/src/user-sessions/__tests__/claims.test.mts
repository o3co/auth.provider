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
import { extractUserClaims } from "../claims.mjs";

describe("extractUserClaims", () => {
	it("maps standard OIDC fields when present", () => {
		const user = {
			id: "user-1",
			username: "alice",
			email: "alice@example.com",
			emailVerified: true,
			name: "Alice",
			picture: "https://example.com/alice.png",
			groups: ["admins"],
		};
		expect(extractUserClaims(user)).toEqual({
			email: "alice@example.com",
			emailVerified: true,
			name: "Alice",
			picture: "https://example.com/alice.png",
			groups: ["admins"],
		});
	});

	it("omits absent fields", () => {
		const user = { id: "u", username: "u" };
		expect(extractUserClaims(user)).toEqual({});
	});

	it("ignores fields of wrong type", () => {
		const user = {
			id: "u",
			username: "u",
			email: 42 as unknown as string,
			groups: "admins" as unknown as string[],
		};
		expect(extractUserClaims(user)).toEqual({});
	});
});
