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
 * An email address as the provider digests, compares and delivers to it, one
 * reading for the coordinator and the email factor alike: two spellings of
 * one mailbox read the same, the local part keeps its case, and a value that
 * is no address reads as none.
 */

import { describe, expect, it } from "vitest";
import { normaliseMailAddress } from "#/index.mjs";

describe("normaliseMailAddress", () => {
	it("reads one mailbox the same whatever its domain's case, the whitespace around it, its Unicode form or its domain's spelling", () => {
		const same = [
			"alice@example.com",
			"alice@Example.COM",
			"  alice@example.com\t",
			"alice@EXAMPLE.COM\n",
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

	it("keeps the local part as it is written: its case is the mailbox's, never lowered", () => {
		expect(normaliseMailAddress("Alice@Example.COM")).toBe("Alice@example.com");
		expect(normaliseMailAddress("  ALICE@EXAMPLE.COM\n")).toBe("ALICE@example.com");
		expect(normaliseMailAddress('"A,B"@Example.com')).toBe('"A,B"@example.com');
		expect(normaliseMailAddress("Alice@example.com")).not.toBe(
			normaliseMailAddress("alice@example.com"),
		);
	});

	it("keeps apart what are two mailboxes", () => {
		expect(normaliseMailAddress("alice@example.com")).not.toBe(
			normaliseMailAddress("alice@example.org"),
		);
		expect(normaliseMailAddress("alice+mfa@example.com")).toBe("alice+mfa@example.com");
		expect(normaliseMailAddress("a.lice@example.com")).toBe("a.lice@example.com");
		expect(normaliseMailAddress('"a,b"@Example.com')).toBe('"a,b"@example.com');
	});

	it("reads no local part a relay could route onward, and no quoted angle bracket: a percent or a bang, a quoted at sign, percent or bang, an encoded word, or a quoted < or > is none", () => {
		for (const value of [
			// Routing operators (#844): a relay may forward on them.
			"victim%evil.example@example.com",
			"evil.example!victim@example.com",
			'"victim@evil.example"@example.com',
			'"victim%evil.example"@example.com',
			'"evil.example!victim"@example.com',
			'"bob@evil.example,carol"@example.com',
			// An encoded word (RFC 2047), which a mail user agent decodes into another address.
			"=?utf-8?q?victim=40evil.example?=@example.com",
			'"=?utf-8?b?dmljdGlt?="@example.com',
			"a=?x?q?y?=b@example.com",
			// An angle bracket inside a quoted local part (#839), which an SMTP envelope refuses.
			'"a<b"@example.com',
			'"a>b"@example.com',
			'"x>bob@evil.example"@example.com',
		]) {
			expect(normaliseMailAddress(value), JSON.stringify(value)).toBeUndefined();
		}
		// What stays readable: `=` and `?` alone, and the rest of atext.
		expect(normaliseMailAddress("a=b?c@example.com")).toBe("a=b?c@example.com");
		expect(normaliseMailAddress('"a=?b"@example.com')).toBe('"a=?b"@example.com');
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

	it("reads what an addr-spec may hold: every atext character but the routing operators, a quoted local part with an escaped character, UTF-8 letters, and the longest local part and label", () => {
		expect(normaliseMailAddress("o'Brien+Tag@example.com")).toBe("o'Brien+Tag@example.com");
		expect(normaliseMailAddress("a#$&'*+-/=?^_`{|}~@example.com")).toBe(
			"a#$&'*+-/=?^_`{|}~@example.com",
		);
		expect(normaliseMailAddress('"a\\"b"@example.com')).toBe('"a\\"b"@example.com');
		expect(normaliseMailAddress("\u7528\u6237@b\u00fccher.example")).toBe(
			"\u7528\u6237@xn--bcher-kva.example",
		);
		const local = "a".repeat(64);
		const label = "b".repeat(63);
		expect(normaliseMailAddress(`${local}@${label}.com`)).toBe(`${local}@${label}.com`);
	});

	it("spells the local part in NFC, its case kept, and holds it within 64 octets as it is spelled", () => {
		// A capital with no precomposed form stays decomposed; a small one composes.
		expect(normaliseMailAddress("J\u030C@example.com")).toBe("J\u030C@example.com");
		expect(normaliseMailAddress("j\u030C@example.com")).toBe("\u01F0@example.com");
		// Two octets each as written, three once lower-cased: the written spelling is what counts.
		expect(normaliseMailAddress(`${"\u0130".repeat(32)}@example.com`)).toBe(
			`${"\u0130".repeat(32)}@example.com`,
		);
		expect(normaliseMailAddress(`${"\u023A".repeat(32)}@example.com`)).toBe(
			`${"\u023A".repeat(32)}@example.com`,
		);
		expect(normaliseMailAddress(`${"\u023A".repeat(33)}@example.com`)).toBeUndefined();
	});

	it("reads what it answers as itself: a second pass changes nothing, at the octet limit too", () => {
		for (const address of [
			"J\u030C@example.com",
			"\u01F0@example.com",
			`${"a".repeat(64)}@example.com`,
			`${"\u023A".repeat(32)}@example.com`,
			`${"\u0130".repeat(32)}@example.com`,
			"Alice@Example.COM",
			`"${"A".repeat(62)}"@Example.COM`,
			`${"b".repeat(63)}@${"c".repeat(63)}.example`,
		]) {
			const once = normaliseMailAddress(address);
			expect(once, JSON.stringify(address)).toBeDefined();
			expect(normaliseMailAddress(once), JSON.stringify(address)).toBe(once);
		}
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
