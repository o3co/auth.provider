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
import { describe, expect, it, vi } from "vitest";
import { resolvePkceSupportedMethods } from "#/grants/pkce.mjs";

describe("resolvePkceSupportedMethods (TS-4)", () => {
	it("returns the valid string array unchanged", () => {
		const result = resolvePkceSupportedMethods({ supportedMethods: ["S256", "plain"] });
		expect(result).toEqual(["S256", "plain"]);
	});

	it("filters non-string elements and warns via the optional logger", () => {
		const logger = {
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
			fatal: vi.fn(),
			child: vi.fn(),
		};
		const result = resolvePkceSupportedMethods(
			{ supportedMethods: ["S256", 123, null, "plain"] },
			logger,
		);
		expect(result).toEqual(["S256", "plain"]);
		expect(logger.warn).toHaveBeenCalledTimes(1);
	});

	it("does NOT warn when no filtering is needed (all elements are strings)", () => {
		const logger = {
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
			fatal: vi.fn(),
			child: vi.fn(),
		};
		resolvePkceSupportedMethods({ supportedMethods: ["S256"] }, logger);
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it("falls back to default when supportedMethods is the empty array literal", () => {
		const result = resolvePkceSupportedMethods({ supportedMethods: [] });
		expect(result).toEqual(["S256", "plain"]);
	});

	it("falls back to default when all elements are non-string (filtered to empty)", () => {
		const result = resolvePkceSupportedMethods({ supportedMethods: [123, null] });
		expect(result).toEqual(["S256", "plain"]);
	});

	it("falls back to default when supportedMethods is absent", () => {
		const result = resolvePkceSupportedMethods({});
		expect(result).toEqual(["S256", "plain"]);
	});

	it("falls back to default when supportedMethods is not an array (e.g. a string)", () => {
		const result = resolvePkceSupportedMethods({
			supportedMethods: "S256",
		} as unknown as Record<string, unknown>);
		expect(result).toEqual(["S256", "plain"]);
	});

	it("falls back to default when pkceConfig itself is undefined", () => {
		const result = resolvePkceSupportedMethods(undefined);
		expect(result).toEqual(["S256", "plain"]);
	});
});

// SF-3 + MIN-4 (v0.5.1) — PKCE timing-safe comparison regression guard.
//
// The fix replaces `!==` with `constantTimeStringEqual`. Pure behavioural
// tests (a "wrong verifier returns 400") cannot detect a regression to
// `!==` because both implementations are functionally equivalent on a
// fixed input. ESM-level `vi.spyOn` is unreliable here: the consumer
// imports `constantTimeStringEqual` from `@o3co/auth-provider-core` and
// holds its own immutable binding, so a post-hoc spy on the namespace
// object would not intercept the call. The most reliable guard is a
// source-level assertion: the production source must reference the
// helper and must not contain the original `!==` shape against
// `codeData.code_challenge`. Codex Delta 2 explicitly accepts this
// "comment-anchored test" alternative.
describe("SF-3 + MIN-4: authorization.mts uses constantTimeStringEqual (regression guard)", () => {
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
