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
 * proxy.test.mts — trusted-proxy allowlist matcher (#280).
 *
 * The matcher answers exactly one question: "is the peer that opened this TCP
 * connection an allowlisted reverse proxy?". It is compared against
 * `req.socket.remoteAddress` — never `req.ip`, which is derived from
 * `X-Forwarded-For` and is therefore attacker-controlled.
 */

import { describe, expect, it } from "vitest";
import { createTrustedProxyMatcher } from "#/proxy.mjs";

describe("createTrustedProxyMatcher — empty allowlist", () => {
	it("trusts nothing when the allowlist is empty (fail closed)", () => {
		const isTrusted = createTrustedProxyMatcher([]);
		expect(isTrusted("127.0.0.1")).toBe(false);
		expect(isTrusted("::1")).toBe(false);
		expect(isTrusted("10.0.0.7")).toBe(false);
	});
});

describe("createTrustedProxyMatcher — literal addresses", () => {
	it("matches an exact IPv4 literal", () => {
		const isTrusted = createTrustedProxyMatcher(["10.0.0.7"]);
		expect(isTrusted("10.0.0.7")).toBe(true);
		expect(isTrusted("10.0.0.8")).toBe(false);
	});

	it("matches an IPv4 rule against the IPv4-mapped IPv6 form Node reports on a dual-stack listener", () => {
		// A Node server bound to `::` reports `::ffff:10.0.0.7` for an IPv4 peer.
		// An operator writes `10.0.0.7` in config and must not have to know that.
		const isTrusted = createTrustedProxyMatcher(["10.0.0.7"]);
		expect(isTrusted("::ffff:10.0.0.7")).toBe(true);
		expect(isTrusted("::ffff:10.0.0.8")).toBe(false);
	});

	it("matches an IPv6 literal regardless of textual form", () => {
		const isTrusted = createTrustedProxyMatcher(["2001:db8::1"]);
		expect(isTrusted("2001:db8::1")).toBe(true);
		expect(isTrusted("2001:0db8:0000:0000:0000:0000:0000:0001")).toBe(true);
		expect(isTrusted("2001:db8::2")).toBe(false);
	});

	it("ignores an IPv6 zone index on the observed address", () => {
		const isTrusted = createTrustedProxyMatcher(["fe80::1"]);
		expect(isTrusted("fe80::1%en0")).toBe(true);
	});

	it("matches any entry in a multi-entry allowlist", () => {
		const isTrusted = createTrustedProxyMatcher(["10.0.0.7", "192.168.1.5", "::1"]);
		expect(isTrusted("10.0.0.7")).toBe(true);
		expect(isTrusted("192.168.1.5")).toBe(true);
		expect(isTrusted("::1")).toBe(true);
		expect(isTrusted("192.168.1.6")).toBe(false);
	});
});

describe("createTrustedProxyMatcher — the `loopback` keyword", () => {
	it("matches the IPv4 loopback block and the IPv6 loopback address", () => {
		const isTrusted = createTrustedProxyMatcher(["loopback"]);
		expect(isTrusted("127.0.0.1")).toBe(true);
		expect(isTrusted("127.0.0.5")).toBe(true);
		expect(isTrusted("::1")).toBe(true);
		expect(isTrusted("::ffff:127.0.0.1")).toBe(true);
	});

	it("does not match a non-loopback address", () => {
		const isTrusted = createTrustedProxyMatcher(["loopback"]);
		expect(isTrusted("10.0.0.7")).toBe(false);
		expect(isTrusted("::ffff:10.0.0.7")).toBe(false);
	});
});

describe("createTrustedProxyMatcher — unusable peer addresses", () => {
	it("returns false when the peer address is undefined (destroyed socket / non-IP transport)", () => {
		// `req.socket.remoteAddress` is `undefined` on a socket that has already
		// been destroyed, and on a Unix-domain-socket listener. Neither can be
		// proven to be the configured proxy, so neither is trusted.
		const isTrusted = createTrustedProxyMatcher(["loopback"]);
		expect(isTrusted(undefined)).toBe(false);
	});

	it("returns false for a peer address that is not an IP at all", () => {
		const isTrusted = createTrustedProxyMatcher(["loopback"]);
		expect(isTrusted("")).toBe(false);
		expect(isTrusted("not-an-address")).toBe(false);
	});
});

describe("createTrustedProxyMatcher — boot-time entry validation", () => {
	it("throws on an entry that is neither a keyword nor an IP literal", () => {
		// A typo'd or hostname entry would silently never match, turning a
		// deliberate allowlist into "trust nothing" at 3am. Fail at boot instead.
		expect(() => createTrustedProxyMatcher(["proxy.internal"])).toThrow(/not a valid IP address/i);
	});

	it("throws on a CIDR entry with a pointer to the follow-up that will add ranges", () => {
		// CIDR ranges are deliberately not supported yet — the shared trust-proxy
		// vocabulary lands with issue #292. Accepting the string and never
		// matching it would be the worst of both worlds.
		expect(() => createTrustedProxyMatcher(["10.0.0.0/8"])).toThrow(/CIDR/i);
		expect(() => createTrustedProxyMatcher(["10.0.0.0/8"])).toThrow(/#292/);
	});

	it("names the offending index so an operator can find it in a long list", () => {
		expect(() => createTrustedProxyMatcher(["loopback", "10.0.0.7", "nope"])).toThrow(/\[2\]/);
	});
});
