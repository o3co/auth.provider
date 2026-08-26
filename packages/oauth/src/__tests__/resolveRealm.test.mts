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
 * `resolveRealm` is the single filter every `WWW-Authenticate: Basic` emission
 * site routes through. Since #266 the routers always hand it a configured
 * canonical issuer, so its degrade-to-"oauth" branch is no longer reachable
 * from a route — it is pinned here directly, because the helper is exported and
 * a library consumer can still pass an unusable value.
 */

import { describe, expect, it } from "vitest";
import { resolveRealm } from "#/middleware/clientAuth.mjs";

describe("resolveRealm", () => {
	it("emits an absolute issuer URL verbatim", () => {
		expect(resolveRealm("https://auth.example")).toBe("https://auth.example");
	});

	it("degrades to the literal oauth when no issuer is supplied", () => {
		expect(resolveRealm(undefined)).toBe("oauth");
		expect(resolveRealm("")).toBe("oauth");
	});

	it.each([
		// `"` terminates the quoted-string; `\\` is the escape byte; a CTL byte is
		// forbidden outright by RFC 7230.
		'evil.example" injected="1',
		"auth\\example",
		`auth${String.fromCharCode(1)}example`,
	])("degrades to the literal oauth rather than emitting %j", (value) => {
		expect(resolveRealm(value)).toBe("oauth");
	});
});
