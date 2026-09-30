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
 * An email address as the provider digests and compares it, one reading for
 * the coordinator and the email factor alike: two spellings of one mailbox
 * read the same, and a value that is no address reads as none.
 */

import { describe, expect, it } from "vitest";
import { normaliseMailAddress } from "#/index.mjs";

describe("normaliseMailAddress", () => {
	it("reads one mailbox the same whatever its case, the whitespace around it, its Unicode form or its domain's spelling", () => {
		const same = [
			"alice@example.com",
			"Alice@Example.COM",
			"  alice@example.com\t",
			"ALICE@EXAMPLE.COM\n",
		];
		for (const address of same) {
			expect(normaliseMailAddress(address), JSON.stringify(address)).toBe("alice@example.com");
		}
		// Composed and decomposed forms of one character are one address.
		expect(normaliseMailAddress("josé@example.com")).toBe(normaliseMailAddress("josé@example.com"));
		// A domain in Unicode and in its ASCII form (IDNA) is one domain.
		expect(normaliseMailAddress("user@bücher.example")).toBe("user@xn--bcher-kva.example");
		expect(normaliseMailAddress("user@XN--BCHER-KVA.example")).toBe("user@xn--bcher-kva.example");
	});

	it("keeps apart what are two mailboxes", () => {
		expect(normaliseMailAddress("alice@example.com")).not.toBe(
			normaliseMailAddress("alice@example.org"),
		);
		expect(normaliseMailAddress("alice+mfa@example.com")).toBe("alice+mfa@example.com");
		expect(normaliseMailAddress("a.lice@example.com")).toBe("a.lice@example.com");
		// The last `@` splits: a quoted local part may hold one.
		expect(normaliseMailAddress('"a@b"@Example.com')).toBe('"a@b"@example.com');
	});

	it("reads a value that is no address as none", () => {
		for (const value of [
			undefined,
			null,
			42,
			{},
			"",
			"   ",
			"alice",
			"alice@",
			"@example.com",
			"ali ce@example.com",
			"alice@exa mple.com",
			"alice@example.com\r\nBcc: mallory@example.com",
			"alice\u0000@example.com",
			"alice\u0085@example.com",
			"alice\uD800@example.com",
			"alice@-invalid-.example..com",
		]) {
			expect(normaliseMailAddress(value), JSON.stringify(value)).toBeUndefined();
		}
	});
});
