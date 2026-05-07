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
import type { Client, Code, CodeData, User } from "../repositories/types.mjs";

// CC-5 readonly compile-time assertions for repository DTOs. See
// readonly-types.test.mts in oauth-token-exchange for the rationale.

describe("CC-5: repository DTOs readonly (compile-time)", () => {
	it("User fields are readonly", () => {
		if (false as boolean) {
			const u = { id: "x", username: "y" } as User;
			// @ts-expect-error — readonly violation
			u.id = "z";
			// @ts-expect-error — readonly violation
			u.username = "z";
			void u;
		}
		expect(true).toBe(true);
	});

	it("Client array fields are readonly arrays (push/element-mutation rejected)", () => {
		if (false as boolean) {
			const c = {} as Client;
			// @ts-expect-error — element mutation on readonly array
			c.allowedRedirectUris.push("extra");
			// @ts-expect-error — element mutation on readonly array
			c.allowedScopes.push("extra");
			// @ts-expect-error — wholesale array replacement on readonly property
			c.allowedRedirectUris = [];
			// @ts-expect-error — wholesale array replacement on readonly property
			c.allowedScopes = [];
			void c;
		}
		expect(true).toBe(true);
	});

	it("CodeData fields are readonly", () => {
		if (false as boolean) {
			const cd = { client_id: "c", redirect_uri: "u" } as CodeData;
			// @ts-expect-error — readonly violation
			cd.client_id = "x";
			// @ts-expect-error — readonly violation
			cd.redirect_uri = "x";
			// @ts-expect-error — readonly violation
			cd.code_challenge = "x";
			// @ts-expect-error — readonly violation
			cd.code_challenge_method = "x";
			// @ts-expect-error — readonly violation
			cd.nonce = "x";
			// @ts-expect-error — readonly violation
			cd.sid = "x";
			void cd;
		}
		expect(true).toBe(true);
	});

	it("Code fields are readonly (incl. inherited CodeData fields)", () => {
		if (false as boolean) {
			const code = { code: "k", client_id: "c", redirect_uri: "u" } as Code;
			// @ts-expect-error — readonly violation
			code.code = "y";
			// @ts-expect-error — readonly violation
			code.expiresIn = 1;
			// @ts-expect-error — readonly violation
			code.grantedScope = [];
			// @ts-expect-error — readonly violation
			code.grantedAudience = [];
			void code;
		}
		expect(true).toBe(true);
	});
});
