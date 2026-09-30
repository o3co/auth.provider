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

	it("reads one addr-spec alone: a list, an angle address, a comment, a format character, or a domain a URL parser would cut short or decode is none", () => {
		for (const value of [
			"attacker@evil.com,victim@example.com",
			"victim@example.com;attacker@evil.com",
			"<attacker@evil.com>@example.com",
			"<victim@example.com>",
			"Victim<victim@example.com>",
			"victim(c)@example.com",
			"victim@example.com(evil.com)",
			"vic:tim@example.com",
			"vic[tim]@example.com",
			"vic\\tim@example.com",
			"ali\u200Bce@example.com",
			"alice\u202E@example.com",
			"alice@exa\u200Bmple.com",
			"alice@exa\u00ADmple.com",
			"alice@example.com\uFEFF",
			"alice@example.com/x",
			"alice@example.com?x",
			"alice@example.com#x",
			"alice@example.com\\x",
			"alice@ex%61mple.com",
			"alice@example.com:25",
			"victim@[127.0.0.1]",
			"alice@\uFF45\uFF58\uFF41\uFF4D\uFF50\uFF4C\uFF45.com",
			"alice@example\u3002com",
			"alice\uFF20example.com",
			"alice@-example.com",
			"alice@example-.com",
			".alice@example.com",
			"alice.@example.com",
			"al..ice@example.com",
			'a"b@example.com',
			'"a"b@example.com',
			'"a\\"@example.com',
			`${"a".repeat(65)}@example.com`,
			`alice@${"b".repeat(64)}.com`,
		]) {
			expect(normaliseMailAddress(value), JSON.stringify(value)).toBeUndefined();
		}
	});

	it("reads what an addr-spec may hold: every atext character, a quoted local part with an escaped character, UTF-8 letters, and the longest local part and label", () => {
		expect(normaliseMailAddress("o'Brien+Tag@example.com")).toBe("o'brien+tag@example.com");
		expect(normaliseMailAddress("a!#$%&'*+-/=?^_`{|}~@example.com")).toBe(
			"a!#$%&'*+-/=?^_`{|}~@example.com",
		);
		expect(normaliseMailAddress('"a\\"b"@example.com')).toBe('"a\\"b"@example.com');
		expect(normaliseMailAddress("\u7528\u6237@b\u00fccher.example")).toBe(
			"\u7528\u6237@xn--bcher-kva.example",
		);
		const local = "a".repeat(64);
		const label = "b".repeat(63);
		expect(normaliseMailAddress(`${local}@${label}.com`)).toBe(`${local}@${label}.com`);
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
