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
import { DPoPError } from "#/errors.mjs";

describe("DPoPError", () => {
	it("hard-codes code to invalid_dpop_proof", () => {
		const err = new DPoPError("htu_mismatch", "no match");
		expect(err.code).toBe("invalid_dpop_proof");
		expect(err.reason).toBe("htu_mismatch");
	});

	it("preserves message and optional detail", () => {
		const err = new DPoPError("replay_detected", "seen", { jti: "abc" });
		expect(err.message).toBe("seen");
		expect(err.detail).toEqual({ jti: "abc" });
	});

	it("omits detail when not provided", () => {
		const err = new DPoPError("multiple_headers", "two values");
		expect(err.detail).toBeUndefined();
	});

	it("matches Phase 1 hasOAuthErrorCode pattern (snake_case code)", () => {
		const err = new DPoPError("missing_claim", "no htm");
		expect(/^[a-z][a-z0-9_]*$/.test(err.code)).toBe(true);
	});
});

describe("DPoPError states its own retry instruction (v0.13.0 audit)", () => {
	it("carries one for the nonce refusals, and none for a verdict on the proof", () => {
		for (const reason of ["nonce_required", "nonce_invalid"] as const) {
			expect(new DPoPError(reason, "m").retryInstruction, reason).toMatch(/DPoP-Nonce/);
		}
		expect(new DPoPError("htu_mismatch", "m").retryInstruction).toBeUndefined();
	});
});
