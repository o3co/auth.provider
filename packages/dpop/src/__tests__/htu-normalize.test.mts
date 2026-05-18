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
import { normalizeHtu } from "#/htu-normalize.mjs";

describe("normalizeHtu — RFC 3986 §6.2.2 conformant", () => {
	it("lowercases scheme and host", () => {
		expect(normalizeHtu("HTTPS://AS.Example.com/Token")).toBe("https://as.example.com/Token");
	});

	it("keeps host in ASCII-compatible (Punycode) form", () => {
		// xn-- form preserved; not decoded to unicode
		expect(normalizeHtu("https://xn--80akhbyknj4f.example/path")).toBe(
			"https://xn--80akhbyknj4f.example/path",
		);
	});

	it("removes default port 443 for https", () => {
		expect(normalizeHtu("https://as.example:443/token")).toBe("https://as.example/token");
	});

	it("removes default port 80 for http", () => {
		expect(normalizeHtu("http://as.example:80/token")).toBe("http://as.example/token");
	});

	it("preserves non-default port", () => {
		expect(normalizeHtu("https://as.example:8443/token")).toBe("https://as.example:8443/token");
	});

	it("decodes unreserved characters in path", () => {
		// %7E = ~ (unreserved)
		expect(normalizeHtu("https://as/%7Eu/profile")).toBe("https://as/~u/profile");
	});

	it("preserves percent-encoding for non-unreserved characters", () => {
		// %20 = space (reserved/needs encoding)
		expect(normalizeHtu("https://as/path%20with%20spaces")).toBe("https://as/path%20with%20spaces");
	});

	it("normalizes empty path to /", () => {
		expect(normalizeHtu("https://as.example")).toBe("https://as.example/");
	});

	it("removes dot segments per RFC 3986 §6.2.2.3", () => {
		expect(normalizeHtu("https://as/a/./b")).toBe("https://as/a/b");
		expect(normalizeHtu("https://as/a/../b")).toBe("https://as/b");
		expect(normalizeHtu("https://as/a/b/..")).toBe("https://as/a");
	});

	it("preserves multiple slashes (does not collapse //)", () => {
		expect(normalizeHtu("https://as/a//b")).toBe("https://as/a//b");
	});

	it("preserves trailing slash verbatim", () => {
		expect(normalizeHtu("https://as/token/")).toBe("https://as/token/");
		expect(normalizeHtu("https://as/token")).toBe("https://as/token");
	});

	it("strips query and fragment", () => {
		expect(normalizeHtu("https://as/token?foo=bar#anchor")).toBe("https://as/token");
	});

	it("preserves path case (RFC 3986 §6.2.2.1: scheme-dependent; preserve for http/s)", () => {
		expect(normalizeHtu("https://as/Token/Endpoint")).toBe("https://as/Token/Endpoint");
	});
});
