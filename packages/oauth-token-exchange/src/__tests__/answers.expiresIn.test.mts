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
 * The exchange answers its own time left: the signed token's expiry does not
 * turn it into core's floor of zero, which the exchange refuses instead.
 */

import { describe, expect, it } from "vitest";
import { tokenAnswer } from "#/answers.mjs";

describe("tokenAnswer", () => {
	it("answers the exchange's expires_in, not one computed from the token's expiresAt", () => {
		const elapsed = Math.floor(Date.now() / 1000) - 60;
		const { result } = tokenAnswer({ token: "t", expiresIn: 300, expiresAt: elapsed }, 42);
		if (!("tokens" in result)) expect.fail("expected tokens");
		expect(result.tokens.expires_in).toBe(42);
	});
});
