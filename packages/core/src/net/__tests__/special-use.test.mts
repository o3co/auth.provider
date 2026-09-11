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
import { isSpecialUseAddress } from "#/net/special-use.mjs";

/**
 * #529 — the address ranges a caller-supplied URL must not resolve to. Pinned
 * against RFC 6890's table so a range dropped by accident is a failing test.
 */
describe("isSpecialUseAddress (RFC 6890, #529)", () => {
	it("refuses every IPv4 special-use range", () => {
		for (const ip of [
			"0.0.0.0",
			"0.255.255.255",
			"10.0.0.1",
			"100.64.0.1",
			"100.127.255.254",
			"127.0.0.1",
			"127.255.255.255",
			"169.254.169.254", // the cloud metadata endpoint — the classic SSRF target
			"172.16.0.1",
			"172.31.255.254",
			"192.0.0.1",
			"192.0.2.10",
			"192.88.99.1",
			"192.168.1.1",
			"198.18.0.1",
			"198.19.255.254",
			"198.51.100.7",
			"203.0.113.9",
			"224.0.0.1",
			"239.255.255.255",
			"240.0.0.1",
			"255.255.255.255",
		]) {
			expect(isSpecialUseAddress(ip), ip).toBe(true);
		}
	});

	it("admits public IPv4 addresses", () => {
		for (const ip of [
			"1.1.1.1",
			"8.8.8.8",
			"93.184.216.34",
			"100.63.255.255",
			"172.32.0.1",
			"198.20.0.1",
		]) {
			expect(isSpecialUseAddress(ip), ip).toBe(false);
		}
	});

	it("refuses every IPv6 special-use range, the IPv4-mapped forms by their IPv4 half", () => {
		for (const ip of [
			"::",
			"::1",
			"::ffff:127.0.0.1",
			"::ffff:10.1.2.3",
			"::ffff:169.254.169.254",
			"::10.0.0.1",
			"64:ff9b::a00:1",
			"100::1",
			"2001::1",
			"2001:db8::1",
			"2002:c000:204::1",
			"fc00::1",
			"fd12:3456::1",
			"fe80::1",
			"ff02::1",
		]) {
			expect(isSpecialUseAddress(ip), ip).toBe(true);
		}
	});

	it("admits public IPv6 addresses, and IPv4-mapped public ones", () => {
		for (const ip of ["2606:4700:4700::1111", "2a00:1450:4001:80e::200e", "::ffff:8.8.8.8"]) {
			expect(isSpecialUseAddress(ip), ip).toBe(false);
		}
	});

	it("answers false for anything that is not an IP address — names are resolved first", () => {
		expect(isSpecialUseAddress("localhost")).toBe(false);
		expect(isSpecialUseAddress("example.com")).toBe(false);
		expect(isSpecialUseAddress("")).toBe(false);
	});
});
