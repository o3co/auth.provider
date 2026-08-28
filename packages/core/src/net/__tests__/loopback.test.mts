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
 * loopback.test.mts — the single loopback-hostname vocabulary (#364).
 *
 * Three consumers share this predicate and must not drift apart:
 *   - `checkSecureEndpoint` (`@o3co/auth-provider-foundation`, #285): `http://`
 *     Store URLs are accepted for loopback hosts only.
 *   - `checkRedirectShape` (`@o3co/auth-provider-session`, #278): `http://`
 *     redirect targets are accepted for loopback hosts only.
 *   - the operator-facing carve-out prose both of them print, which promises
 *     "localhost, 127.0.0.0/8, [::1]" — this suite is that promise, executable.
 *
 * Before #364 the predicate existed as two sibling copies whose doc comments
 * were identical and whose behavior was not (`"::1"` unbracketed was accepted
 * by one and not the other) — the copies drifted one commit after the decision
 * not to unify them was written down. The unified predicate accepts the union:
 * both are loopback, and treating either form as non-loopback was never a
 * decision anyone made.
 */

import { describe, expect, it } from "vitest";
import { isLoopbackHostname } from "../loopback.mjs";

describe("isLoopbackHostname", () => {
	it.each([
		// The name the carve-out is for.
		"localhost",
		// IPv6 loopback as URL.hostname reports it (always bracketed)...
		"[::1]",
		// ...and as a raw hostname outside a URL (what a config value or a
		// socket API hands over). Both denote the same address; accepting only
		// one form is how the pre-#364 copies drifted.
		"::1",
		// The whole 127.0.0.0/8 block is loopback, not just 127.0.0.1 —
		// 127.0.0.53 is systemd-resolved, and containers report others.
		"127.0.0.1",
		"127.0.0.53",
		"127.255.255.255",
	])("accepts %s", (hostname) => {
		expect(isLoopbackHostname(hostname)).toBe(true);
	});

	it.each([
		// Off-by-one neighbours of the /8 block.
		"126.255.255.255",
		"128.0.0.1",
		// Private-range and public hosts: "internal" is not "loopback".
		"10.0.0.5",
		"192.168.1.1",
		"example.com",
		// An octet out of range is not an IPv4 address at all.
		"127.0.0.256",
		// IPv4 shorthand ("127.1") is NOT accepted here: URL.hostname has
		// already normalized shorthand to dotted quad, and a raw config value
		// spelled that way is a typo more often than an intent.
		"127.1",
		"127.0.0",
		// Suffix/prefix tricks around the literal name.
		"localhost.example.com",
		"evil-localhost",
		// Full-form IPv6 loopback is out of contract: URL.hostname always
		// compresses to [::1], and accepting textual variants open-endedly is
		// how a comparison becomes a parser.
		"0:0:0:0:0:0:0:1",
		"[::2]",
		"::2",
		"",
	])("rejects %s", (hostname) => {
		expect(isLoopbackHostname(hostname)).toBe(false);
	});
});
