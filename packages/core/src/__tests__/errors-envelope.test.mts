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
import { errorEnvelope } from "../errors/envelope.mjs";

describe("AS-1/AS-2 errorEnvelope helper (RFC 6749 §5.2)", () => {
	it("includes error_description and error_uri when provided", () => {
		const e = errorEnvelope("invalid_grant", "Token expired", "https://docs.example.com");
		expect(e).toEqual({
			error: "invalid_grant",
			error_description: "Token expired",
			error_uri: "https://docs.example.com",
		});
	});

	it("omits optional fields when undefined", () => {
		const e = errorEnvelope("not_found");
		expect(e).toEqual({ error: "not_found" });
		expect(e).not.toHaveProperty("error_description");
		expect(e).not.toHaveProperty("error_uri");
	});

	it("includes error_description without error_uri", () => {
		const e = errorEnvelope("server_error", "Session regeneration failed");
		expect(e).toEqual({
			error: "server_error",
			error_description: "Session regeneration failed",
		});
		expect(e).not.toHaveProperty("error_uri");
	});

	it("treats undefined description as omission, not as a present empty value", () => {
		const e = errorEnvelope("rate_limited", undefined);
		expect(Object.keys(e).sort()).toEqual(["error"]);
	});
});
