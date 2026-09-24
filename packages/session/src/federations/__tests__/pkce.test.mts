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
import { generateCodeVerifier } from "#/federations/pkce.mjs";

describe("generateCodeVerifier", () => {
	it("produces a 43-character base64url string (RFC 7636 §4.1)", () => {
		const v = generateCodeVerifier();
		expect(v).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(v.length).toBe(43);
	});

	it("produces a different value on each call (cryptographically random)", () => {
		const set = new Set<string>();
		for (let i = 0; i < 100; i++) set.add(generateCodeVerifier());
		expect(set.size).toBe(100);
	});
});
