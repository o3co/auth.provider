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

import { BlockList, isIP } from "node:net";

/**
 * The IPv4 and IPv6 special-use address ranges of RFC 6890 (with the RFC
 * 8190 additions) — loopback, private, link-local, CGNAT, documentation,
 * benchmarking, multicast, reserved, unique-local, and the IPv4-mapped and
 * IPv4-compatible IPv6 forms of all of them.
 *
 * One list, so every "this URL must not point inside the network" decision
 * (#529's Client ID Metadata Document fetch, and whatever fetches a
 * caller-supplied URL next) refuses the same addresses.
 */
const SPECIAL_USE = new BlockList();
for (const [net, prefix] of [
	["0.0.0.0", 8], // "this" network, RFC 1122
	["10.0.0.0", 8], // private, RFC 1918
	["100.64.0.0", 10], // shared address space (CGNAT), RFC 6598
	["127.0.0.0", 8], // loopback
	["169.254.0.0", 16], // link-local, RFC 3927
	["172.16.0.0", 12], // private
	["192.0.0.0", 24], // IETF protocol assignments, RFC 6890
	["192.0.2.0", 24], // TEST-NET-1
	["192.88.99.0", 24], // 6to4 relay anycast (deprecated), RFC 7526
	["192.168.0.0", 16], // private
	["198.18.0.0", 15], // benchmarking, RFC 2544
	["198.51.100.0", 24], // TEST-NET-2
	["203.0.113.0", 24], // TEST-NET-3
	["224.0.0.0", 4], // multicast
	["240.0.0.0", 4], // reserved, incl. broadcast
] as const) {
	SPECIAL_USE.addSubnet(net, prefix, "ipv4");
}
for (const [net, prefix] of [
	["::", 128], // unspecified
	["::1", 128], // loopback
	// The IPv4-mapped (::ffff:0:0/96) and IPv4-compatible (::/96) forms are
	// NOT listed as subnets: Node checks an IPv4 address against IPv6 rules
	// through its mapped form, so either subnet would refuse every IPv4
	// address. Both forms are judged by their IPv4 half below instead.
	["64:ff9b::", 96], // IPv4/IPv6 translation, RFC 6052
	["100::", 64], // discard-only, RFC 6666
	["2001::", 23], // IETF protocol assignments (TEREDO, ORCHID, …)
	["2001:db8::", 32], // documentation
	["2002::", 16], // 6to4
	["fc00::", 7], // unique local, RFC 4193
	["fe80::", 10], // link-local
	["ff00::", 8], // multicast
] as const) {
	SPECIAL_USE.addSubnet(net, prefix, "ipv6");
}

/**
 * Whether `address` is an IP literal inside a special-use range (RFC 6890):
 * one that names this host, this network, a private network, a documentation
 * or benchmarking block, or a multicast / reserved block — none of which a
 * URL supplied by an untrusted party may legitimately resolve to.
 *
 * An IPv4-mapped IPv6 address (`::ffff:10.0.0.1`) is judged by its IPv4
 * half. A string that is not an IP address at all answers `false`: the
 * caller resolves names first and asks about each address.
 */
export function isSpecialUseAddress(address: string): boolean {
	const family = isIP(address);
	if (family === 4) return SPECIAL_USE.check(address, "ipv4");
	if (family === 6) {
		// `::ffff:a.b.c.d` (mapped) and `::a.b.c.d` (compatible, deprecated):
		// the IPv4 half is what the packet reaches.
		const embedded = /^::(?:ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address);
		if (embedded?.[1] !== undefined && isIP(embedded[1]) === 4) {
			return SPECIAL_USE.check(embedded[1], "ipv4");
		}
		return SPECIAL_USE.check(address, "ipv6");
	}
	return false;
}
