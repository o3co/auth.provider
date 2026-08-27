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
 * trusted-proxy.test.mts — the single trusted-proxy address vocabulary (#292).
 *
 * Two consumers share this module and must not drift apart:
 *   - `http.trustProxy` (this package's config schema) validates its entries
 *     here so a typo fails at boot instead of silently never matching.
 *   - `oauth.mtls.trusted-proxies` (`@o3co/auth-provider-mtls`) matches
 *     `req.socket.remoteAddress` against them (#280).
 *
 * The vocabulary is deliberately Express's own `trust proxy` vocabulary, so a
 * value that validates here is a value Express accepts.
 */

import { describe, expect, it } from "vitest";
import {
	checkTrustedProxyEntry,
	createTrustedProxyMatcher,
	describeTrustedProxyEntryRejection,
} from "#/net/trusted-proxy.mjs";

describe("checkTrustedProxyEntry — accepted vocabulary", () => {
	it.each(["loopback", "linklocal", "uniquelocal"])(
		"accepts the Express named range %s",
		(entry) => {
			expect(checkTrustedProxyEntry(entry)).toBeNull();
		},
	);

	it("accepts a named range regardless of case, and with surrounding whitespace", () => {
		expect(checkTrustedProxyEntry("LOOPBACK")).toBeNull();
		expect(checkTrustedProxyEntry("  loopback  ")).toBeNull();
	});

	it.each(["10.0.0.7", "192.168.1.5", "::1", "2001:db8::1", "fe80::1%en0"])(
		"accepts the IP literal %s",
		(entry) => {
			expect(checkTrustedProxyEntry(entry)).toBeNull();
		},
	);

	it.each(["10.0.0.0/8", "172.16.0.0/12", "0.0.0.0/0", "10.0.0.0/32"])(
		"accepts the IPv4 CIDR range %s",
		(entry) => {
			expect(checkTrustedProxyEntry(entry)).toBeNull();
		},
	);

	it.each(["fc00::/7", "2001:db8::/32", "::1/128", "::/0"])(
		"accepts the IPv6 CIDR range %s",
		(entry) => {
			expect(checkTrustedProxyEntry(entry)).toBeNull();
		},
	);
});

describe("checkTrustedProxyEntry — rejected entries", () => {
	it("rejects a non-string", () => {
		expect(checkTrustedProxyEntry(42)).toBe("not-a-string");
		expect(checkTrustedProxyEntry(null)).toBe("not-a-string");
	});

	it("rejects an empty or whitespace-only entry", () => {
		expect(checkTrustedProxyEntry("")).toBe("empty");
		expect(checkTrustedProxyEntry("   ")).toBe("empty");
	});

	it("rejects a hostname — there is no name to resolve on an open connection", () => {
		expect(checkTrustedProxyEntry("proxy.internal")).toBe("not-an-address-or-keyword");
	});

	it("rejects a typo'd keyword rather than treating it as an address", () => {
		expect(checkTrustedProxyEntry("loopbak")).toBe("not-an-address-or-keyword");
	});

	it("rejects a CIDR whose address part is not an IP", () => {
		expect(checkTrustedProxyEntry("proxy.internal/24")).toBe("not-an-address-or-keyword");
	});

	it("rejects a prefix length outside the family's range", () => {
		expect(checkTrustedProxyEntry("10.0.0.0/33")).toBe("bad-prefix-length");
		expect(checkTrustedProxyEntry("fc00::/129")).toBe("bad-prefix-length");
		expect(checkTrustedProxyEntry("10.0.0.0/-1")).toBe("bad-prefix-length");
		expect(checkTrustedProxyEntry("10.0.0.0/eight")).toBe("bad-prefix-length");
		expect(checkTrustedProxyEntry("10.0.0.0/")).toBe("bad-prefix-length");
		expect(checkTrustedProxyEntry("10.0.0.0/08")).toBe("bad-prefix-length");
	});

	it("rejects dotted-netmask notation with its own reason", () => {
		// proxy-addr accepts `10.0.0.0/255.0.0.0`; `BlockList.addSubnet` takes a
		// prefix length only. Rejecting it loudly (rather than accepting a form
		// this matcher cannot express) keeps the two consumers on one vocabulary.
		expect(checkTrustedProxyEntry("10.0.0.0/255.0.0.0")).toBe("netmask-notation");
	});

	it("rejects an entry carrying more than one slash", () => {
		expect(checkTrustedProxyEntry("10.0.0.0/8/8")).toBe("bad-prefix-length");
	});
});

describe("describeTrustedProxyEntryRejection", () => {
	it("returns an operator-facing sentence for every rejection reason", () => {
		const reasons = [
			"not-a-string",
			"empty",
			"not-an-address-or-keyword",
			"bad-prefix-length",
			"netmask-notation",
		] as const;
		for (const reason of reasons) {
			const message = describeTrustedProxyEntryRejection(reason);
			expect(typeof message).toBe("string");
			expect(message.length).toBeGreaterThan(0);
		}
	});

	it("names the prefix-length notation in the netmask message so the fix is obvious", () => {
		expect(describeTrustedProxyEntryRejection("netmask-notation")).toMatch(/prefix length/i);
	});
});

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

describe("createTrustedProxyMatcher — CIDR ranges (#292)", () => {
	it("matches an address inside an IPv4 range and rejects one outside it", () => {
		const isTrusted = createTrustedProxyMatcher(["10.0.0.0/8"]);
		expect(isTrusted("10.0.0.1")).toBe(true);
		expect(isTrusted("10.255.255.254")).toBe(true);
		expect(isTrusted("11.0.0.1")).toBe(false);
	});

	it("matches an IPv4 range against the IPv4-mapped IPv6 form", () => {
		const isTrusted = createTrustedProxyMatcher(["10.0.0.0/8"]);
		expect(isTrusted("::ffff:10.1.2.3")).toBe(true);
		expect(isTrusted("::ffff:11.1.2.3")).toBe(false);
	});

	it("matches an address inside an IPv6 range", () => {
		const isTrusted = createTrustedProxyMatcher(["2001:db8::/32"]);
		expect(isTrusted("2001:db8::1")).toBe(true);
		expect(isTrusted("2001:db9::1")).toBe(false);
	});

	it("masks host bits so an operator writing the proxy's own address with a prefix still gets the range", () => {
		const isTrusted = createTrustedProxyMatcher(["10.4.5.6/16"]);
		expect(isTrusted("10.4.9.9")).toBe(true);
		expect(isTrusted("10.5.0.1")).toBe(false);
	});
});

describe("createTrustedProxyMatcher — named ranges", () => {
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

	it("matches the linklocal ranges", () => {
		const isTrusted = createTrustedProxyMatcher(["linklocal"]);
		expect(isTrusted("169.254.1.1")).toBe(true);
		expect(isTrusted("fe80::1")).toBe(true);
		expect(isTrusted("10.0.0.7")).toBe(false);
	});

	it("matches every uniquelocal range", () => {
		const isTrusted = createTrustedProxyMatcher(["uniquelocal"]);
		expect(isTrusted("10.1.2.3")).toBe(true);
		expect(isTrusted("172.16.0.1")).toBe(true);
		expect(isTrusted("172.31.255.254")).toBe(true);
		expect(isTrusted("192.168.0.1")).toBe(true);
		expect(isTrusted("fd00::1")).toBe(true);
		// 172.32.0.0 is outside 172.16.0.0/12 — the classic off-by-one.
		expect(isTrusted("172.32.0.1")).toBe(false);
		expect(isTrusted("8.8.8.8")).toBe(false);
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
	it("throws on an entry that is neither a named range nor an address", () => {
		// A typo'd or hostname entry would silently never match, turning a
		// deliberate allowlist into "trust nothing" at 3am. Fail at boot instead.
		expect(() => createTrustedProxyMatcher(["proxy.internal"])).toThrow(
			/not an IP address, a CIDR range/i,
		);
	});

	it("throws on a malformed CIDR prefix length", () => {
		expect(() => createTrustedProxyMatcher(["10.0.0.0/33"])).toThrow(/prefix length/i);
	});

	it("names the offending index so an operator can find it in a long list", () => {
		expect(() => createTrustedProxyMatcher(["loopback", "10.0.0.7", "nope"])).toThrow(/\[2\]/);
	});

	it("labels the offending entry with the config key the caller names", () => {
		expect(() => createTrustedProxyMatcher(["nope"], { label: "trusted-proxies" })).toThrow(
			/trusted-proxies\[0\]/,
		);
	});
});
