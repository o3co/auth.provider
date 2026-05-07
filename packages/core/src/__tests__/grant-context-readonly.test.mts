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
import type { GrantContext } from "../grants/types.mjs";

// CC-5 readonly compile-time assertions for GrantContext. See
// readonly-types.test.mts in oauth-token-exchange for the rationale.

describe("CC-5: GrantContext readonly (compile-time)", () => {
	it("GrantContext top-level fields are readonly", () => {
		if (false as boolean) {
			const ctx = {
				body: {},
				session: {},
				issuer: "https://example.com",
				metadata: {},
				ip: "127.0.0.1",
				userAgent: "test",
				authenticatedClient: null,
			} as GrantContext;
			// @ts-expect-error — readonly violation
			ctx.body = {};
			// @ts-expect-error — readonly violation
			ctx.issuer = "other";
			// @ts-expect-error — readonly violation
			ctx.metadata = {};
			// @ts-expect-error — readonly violation
			ctx.ip = "other";
			// @ts-expect-error — readonly violation
			ctx.userAgent = "other";
			// @ts-expect-error — readonly violation (wholesale session replacement)
			ctx.session = {};
			void ctx;
		}
		expect(true).toBe(true);
	});

	it("GrantContext.session field-level mutation still compiles (SessionData fields are mutable)", () => {
		if (false as boolean) {
			const ctx = {
				body: {},
				session: {},
				issuer: "https://example.com",
				metadata: {},
				ip: "127.0.0.1",
				userAgent: "test",
				authenticatedClient: null,
			} as GrantContext;
			// SessionData fields are intentionally mutable — handlers write via req.session
			ctx.session.isAuthenticated = true;
			ctx.session.user = { id: "u" };
			void ctx;
		}
		expect(true).toBe(true);
	});
});
