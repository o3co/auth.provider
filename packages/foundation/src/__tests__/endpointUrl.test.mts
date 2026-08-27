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
import {
	assertSecureEndpoint,
	checkSecureEndpoint,
	describeEndpointRejection,
	type EndpointRejection,
	isLoopbackHostname,
} from "#/endpointUrl.mjs";

describe("isLoopbackHostname", () => {
	it("accepts localhost", () => {
		expect(isLoopbackHostname("localhost")).toBe(true);
	});

	it("accepts every address in 127.0.0.0/8, not just 127.0.0.1", () => {
		// systemd-resolved listens on 127.0.0.53; docker-for-mac and CI
		// fixtures routinely bind other addresses in the /8.
		expect(isLoopbackHostname("127.0.0.1")).toBe(true);
		expect(isLoopbackHostname("127.0.0.53")).toBe(true);
		expect(isLoopbackHostname("127.1.2.3")).toBe(true);
		expect(isLoopbackHostname("127.255.255.254")).toBe(true);
	});

	it("accepts the IPv6 loopback in the bracketed form the URL parser produces", () => {
		expect(isLoopbackHostname("[::1]")).toBe(true);
	});

	it("rejects hosts that merely look loopback", () => {
		expect(isLoopbackHostname("127.0.0.1.example.com")).toBe(false);
		expect(isLoopbackHostname("localhost.example.com")).toBe(false);
		expect(isLoopbackHostname("notlocalhost")).toBe(false);
		expect(isLoopbackHostname("128.0.0.1")).toBe(false);
		expect(isLoopbackHostname("[::2]")).toBe(false);
		expect(isLoopbackHostname("0.0.0.0")).toBe(false);
	});
});

describe("checkSecureEndpoint", () => {
	it("accepts an https URL", () => {
		expect(checkSecureEndpoint("https://users.example.com/authenticate")).toBeNull();
	});

	it("accepts an https URL carrying a query string", () => {
		// Unlike the canonical issuer, a Store endpoint is an ordinary POST
		// target: a tenant selector in the query is legitimate.
		expect(checkSecureEndpoint("https://users.example.com/authenticate?tenant=acme")).toBeNull();
	});

	it("accepts an http URL on a loopback host", () => {
		expect(checkSecureEndpoint("http://localhost:18080/user/authenticate")).toBeNull();
		expect(checkSecureEndpoint("http://127.0.0.1:18080/user/authenticate")).toBeNull();
		expect(checkSecureEndpoint("http://[::1]:18080/user/authenticate")).toBeNull();
	});

	it("normalizes shorthand IPv4 loopback forms before deciding", () => {
		// The WHATWG URL parser rewrites `127.1` to `127.0.0.1`.
		expect(checkSecureEndpoint("http://127.1:18080/authenticate")).toBeNull();
	});

	it("rejects an http URL on a routable host", () => {
		expect(checkSecureEndpoint("http://users.example.com/authenticate")).toBe("insecure-scheme");
		expect(checkSecureEndpoint("http://10.0.0.5/authenticate")).toBe("insecure-scheme");
	});

	it("rejects a non-http(s) scheme", () => {
		expect(checkSecureEndpoint("ftp://users.example.com/authenticate")).toBe("unsupported-scheme");
		expect(checkSecureEndpoint("file:///etc/passwd")).toBe("unsupported-scheme");
	});

	it("rejects a relative or bare-host value", () => {
		expect(checkSecureEndpoint("/user/authenticate")).toBe("not-absolute-url");
		expect(checkSecureEndpoint("users.example.com:3000")).toBe("not-absolute-url");
	});

	it("rejects a value that carries a scheme but does not parse", () => {
		// These get past the `scheme://` prefix test and then throw in `new URL`.
		// They are also why no empty-hostname check is needed: `http`/`https` are
		// "special" schemes, for which the parser requires a non-empty host, so a
		// host-less URL never reaches the loopback comparison.
		expect(checkSecureEndpoint("https://")).toBe("not-absolute-url");
		expect(checkSecureEndpoint("https://:8080/authenticate")).toBe("not-absolute-url");
		expect(checkSecureEndpoint("http://[::1")).toBe("not-absolute-url");
	});

	it("rejects embedded credentials", () => {
		expect(checkSecureEndpoint("https://user:pass@users.example.com/authenticate")).toBe(
			"has-credentials",
		);
	});

	it("rejects non-strings and empties", () => {
		expect(checkSecureEndpoint(undefined)).toBe("not-a-string");
		expect(checkSecureEndpoint(42)).toBe("not-a-string");
		expect(checkSecureEndpoint("")).toBe("empty");
	});
});

describe("describeEndpointRejection", () => {
	const ALL: EndpointRejection[] = [
		"not-a-string",
		"empty",
		"not-absolute-url",
		"unsupported-scheme",
		"insecure-scheme",
		"has-credentials",
	];

	it("explains every rejection reason", () => {
		for (const reason of ALL) {
			const message = describeEndpointRejection(reason);
			expect(message.startsWith("must")).toBe(true);
			expect(message.length).toBeGreaterThan(10);
		}
	});

	// The message an operator reads at boot must state the rule the code
	// actually applies. "must use the https scheme" contradicted a policy that
	// does accept http on loopback, and would send someone hunting for a
	// certificate they do not need.
	it("names the loopback carve-out in BOTH scheme messages", () => {
		for (const reason of ["unsupported-scheme", "insecure-scheme"] as const) {
			const message = describeEndpointRejection(reason);
			expect(message).toMatch(/loopback/);
			expect(message).toMatch(/127\.0\.0\.0\/8/);
		}
	});

	it("does not claim https is unconditionally required", () => {
		expect(describeEndpointRejection("unsupported-scheme")).not.toBe("must use the https scheme");
	});

	it("tells the operator that a blank env var is what produced an empty value", () => {
		expect(describeEndpointRejection("empty")).toMatch(/environment variable/);
	});

	it("names the bare-host mistake, the usual cause of not-absolute-url", () => {
		expect(describeEndpointRejection("not-absolute-url")).toMatch(/bare host/);
	});
});

describe("assertSecureEndpoint", () => {
	it("returns the value when it is usable", () => {
		expect(assertSecureEndpoint("https://users.example.com/authenticate", "authenticateUrl")).toBe(
			"https://users.example.com/authenticate",
		);
	});

	it("carries the reason code alongside the explanation", () => {
		expect(() => assertSecureEndpoint("http://users.example.com/x", "authenticateUrl")).toThrow(
			/\(reason: insecure-scheme\)/,
		);
	});

	it("explains a missing value rather than reporting a bare type error", () => {
		expect(() => assertSecureEndpoint(undefined, "authenticateByTokenUrl")).toThrow(
			/authenticateByTokenUrl.*must be a string/,
		);
		expect(() => assertSecureEndpoint("", "authenticateByTokenUrl")).toThrow(
			/must not be empty.*environment variable/,
		);
	});

	it("names the offending field and explains the loopback carve-out", () => {
		expect(() => assertSecureEndpoint("http://users.example.com/x", "authenticateUrl")).toThrow(
			/authenticateUrl/,
		);
		expect(() => assertSecureEndpoint("http://users.example.com/x", "authenticateUrl")).toThrow(
			/loopback/,
		);
	});

	it("does not echo an embedded password back into the error message", () => {
		// The rejected value is operator-supplied config that may hold a secret;
		// the message names the field and the reason, never the value.
		expect(() =>
			assertSecureEndpoint("https://user:hunter2@users.example.com/x", "authenticateUrl"),
		).toThrow(/authenticateUrl/);
		try {
			assertSecureEndpoint("https://user:hunter2@users.example.com/x", "authenticateUrl");
		} catch (err) {
			expect((err as Error).message).not.toContain("hunter2");
		}
	});
});
