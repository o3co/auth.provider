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

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	PKCE_METHOD_ABSENT_DEFAULT,
	pkceMethodsForClient,
	resolvePkceOptions,
} from "#/grants/pkce.mjs";

describe("resolvePkceOptions", () => {
	it("resolves to required + S256-only", () => {
		expect(resolvePkceOptions()).toEqual({ required: true, supportedMethods: ["S256"] });
	});

	it("returns a frozen supportedMethods list so a consumer cannot widen it in place", () => {
		const { supportedMethods } = resolvePkceOptions();
		expect(Object.isFrozen(supportedMethods)).toBe(true);
	});

	it("returns one policy on every resolution", () => {
		expect(resolvePkceOptions()).toBe(resolvePkceOptions());
	});
});

describe("pkceMethodsForClient", () => {
	// The policy both endpoints hand in — resolved from config, identical on
	// each side. Taking it as a parameter (rather than closing over the
	// constant) is what makes "/authorize and /token read the same object"
	// checkable rather than asserted.
	const policy = resolvePkceOptions();

	it("gives S256 only to a client with no opt-in", () => {
		expect(pkceMethodsForClient(policy, {})).toEqual(["S256"]);
	});

	it("gives S256 only to a null / undefined client", () => {
		expect(pkceMethodsForClient(policy, null)).toEqual(["S256"]);
		expect(pkceMethodsForClient(policy, undefined)).toEqual(["S256"]);
	});

	it("returns the policy's own baseline list, not a copy of it", () => {
		expect(pkceMethodsForClient(policy, null)).toBe(policy.supportedMethods);
	});

	it("adds plain only on a literal `true` opt-in", () => {
		expect(pkceMethodsForClient(policy, { allowPlainPkce: true })).toEqual(["S256", "plain"]);
	});

	it("does not widen on a truthy non-boolean (an uncoerced YAML/env string)", () => {
		expect(
			pkceMethodsForClient(policy, { allowPlainPkce: "true" } as unknown as {
				allowPlainPkce?: boolean;
			}),
		).toEqual(["S256"]);
	});

	it("returns frozen lists", () => {
		expect(Object.isFrozen(pkceMethodsForClient(policy, {}))).toBe(true);
		expect(Object.isFrozen(pkceMethodsForClient(policy, { allowPlainPkce: true }))).toBe(true);
	});
});

describe("PKCE_METHOD_ABSENT_DEFAULT", () => {
	it("is RFC 7636 §4.3's `plain`, so an omitted method is refused unless plain is opted in", () => {
		// The constant exists so both endpoints agree on what an absent
		// `code_challenge_method` means. It must stay `plain`: reading absence
		// as S256 would hash a verifier the client computed as a plain
		// challenge and fail at redemption instead of at the request boundary.
		expect(PKCE_METHOD_ABSENT_DEFAULT).toBe("plain");
	});
});

// PKCE verifiers are compared in constant time, pinned at the source level:
// a behavioural test cannot tell `!==` from `constantTimeStringEqual` on a
// fixed input, and `vi.spyOn` cannot intercept the call, since the consumer
// holds its own immutable ESM binding of the import from
// `@o3co/auth-provider-core`.
describe("authorization.mts uses constantTimeStringEqual", () => {
	const authorizationSource = readFileSync(
		resolve(dirname(fileURLToPath(import.meta.url)), "../authorization.mts"),
		"utf8",
	);

	it("imports and uses constantTimeStringEqual", () => {
		expect(authorizationSource).toMatch(/\bconstantTimeStringEqual\b/);
	});

	it("does NOT contain the pre-fix S256 `base64url !== codeData.code_challenge` compare", () => {
		expect(authorizationSource).not.toMatch(/base64url\s*!==\s*codeData\.code_challenge\b/);
	});

	it("does NOT contain the pre-fix plain `code_verifier !== codeData.code_challenge` compare", () => {
		expect(authorizationSource).not.toMatch(/code_verifier\s*!==\s*codeData\.code_challenge\b/);
	});
});
