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
import {
	PKCE_METHOD_ABSENT_DEFAULT,
	pkceMethodsForClient,
	resolvePkceOptions,
} from "#/grants/pkce.mjs";

const makeLogger = () => ({
	trace: vi.fn(),
	debug: vi.fn(),
	info: vi.fn(),
	warn: vi.fn(),
	error: vi.fn(),
	fatal: vi.fn(),
	child: vi.fn(),
});

describe("resolvePkceOptions (#273)", () => {
	it("resolves to required + S256-only when no pkce block is configured", () => {
		expect(resolvePkceOptions(undefined)).toEqual({ required: true, supportedMethods: ["S256"] });
	});

	it("resolves to the same object shape for an empty pkce block", () => {
		expect(resolvePkceOptions({})).toEqual({ required: true, supportedMethods: ["S256"] });
	});

	it("returns a frozen supportedMethods list so a consumer cannot widen it in place", () => {
		const { supportedMethods } = resolvePkceOptions(undefined);
		expect(Object.isFrozen(supportedMethods)).toBe(true);
	});

	it("cannot be turned off: `required = false` is inert", () => {
		expect(resolvePkceOptions({ required: false }).required).toBe(true);
	});

	it("cannot re-admit plain through the global supportedMethods allowlist", () => {
		// Pre-#273 this list was the operator-facing knob and defaulted to
		// ["S256","plain"]. `plain` is now reachable ONLY per client.
		expect(resolvePkceOptions({ supportedMethods: ["S256", "plain"] }).supportedMethods).toEqual([
			"S256",
		]);
		expect(resolvePkceOptions({ supportedMethods: ["plain"] }).supportedMethods).toEqual(["S256"]);
	});

	it("cannot re-admit plain through the legacy defaultMethod knob", () => {
		expect(resolvePkceOptions({ defaultMethod: "plain" }).supportedMethods).toEqual(["S256"]);
	});

	it("ignores the legacy requireS256 boolean in both directions", () => {
		expect(resolvePkceOptions({ requireS256: false })).toEqual({
			required: true,
			supportedMethods: ["S256"],
		});
		expect(resolvePkceOptions({ requireS256: true })).toEqual({
			required: true,
			supportedMethods: ["S256"],
		});
	});

	it("warns once, naming every inert key, so an operator sees the config is dead", () => {
		const logger = makeLogger();
		resolvePkceOptions(
			{ requireS256: false, required: false, defaultMethod: "plain", supportedMethods: ["plain"] },
			logger,
		);
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({
				ignoredKeys: ["requireS256", "required", "defaultMethod", "supportedMethods"],
			}),
			"pkce_config_ignored_s256_is_mandatory",
		);
	});

	it("stays silent when the operator configured nothing", () => {
		const logger = makeLogger();
		resolvePkceOptions(undefined, logger);
		resolvePkceOptions({}, logger);
		expect(logger.warn).not.toHaveBeenCalled();
	});

	// `resolveOAuthOptions` runs more than once per boot — `createOAuthRouter`
	// resolves it for the routers and `createAuthorizationGrant` resolves it
	// again for the token endpoint. That duplication is deliberate (it is what
	// makes both endpoints read one policy) but it made the "your config is
	// inert" line fire once per resolution instead of once per deployment.
	describe("warns once per config, not once per resolution", () => {
		it("emits a single warning however many times one config is resolved", () => {
			const logger = makeLogger();
			const pkceConfig = { requireS256: false };
			resolvePkceOptions(pkceConfig, logger);
			resolvePkceOptions(pkceConfig, logger);
			resolvePkceOptions(pkceConfig, logger);
			expect(logger.warn).toHaveBeenCalledTimes(1);
		});

		it("still warns for a DIFFERENT config in the same process", () => {
			// The reason this is not a module-level boolean: a process that
			// composes several deployments — every test file in this package,
			// and any embedder building more than one AS — would otherwise warn
			// for the first stale config and go silent for every later one,
			// which is worse than warning twice.
			const logger = makeLogger();
			resolvePkceOptions({ requireS256: false }, logger);
			resolvePkceOptions({ defaultMethod: "plain" }, logger);
			expect(logger.warn).toHaveBeenCalledTimes(2);
			expect(logger.warn).toHaveBeenNthCalledWith(
				1,
				expect.objectContaining({ ignoredKeys: ["requireS256"] }),
				"pkce_config_ignored_s256_is_mandatory",
			);
			expect(logger.warn).toHaveBeenNthCalledWith(
				2,
				expect.objectContaining({ ignoredKeys: ["defaultMethod"] }),
				"pkce_config_ignored_s256_is_mandatory",
			);
		});

		it("does not let one logger's suppression hide the config from another", () => {
			// Two loggers, one config: the second resolution is genuinely the
			// same deployment being resolved again, so silence is correct —
			// this pins that the key is the CONFIG, not the logger.
			const first = makeLogger();
			const second = makeLogger();
			const pkceConfig = { supportedMethods: ["plain"] };
			resolvePkceOptions(pkceConfig, first);
			resolvePkceOptions(pkceConfig, second);
			expect(first.warn).toHaveBeenCalledTimes(1);
			expect(second.warn).not.toHaveBeenCalled();
		});

		it("does not let a logger-less resolution consume the warning", () => {
			// `grants/session.mts` resolves the same options object with no
			// logger. If that call marked the config as reported, whether an
			// operator ever saw the warning would depend on module construction
			// order — silence for a real misconfiguration, intermittently.
			const logger = makeLogger();
			const pkceConfig = { requireS256: true };
			resolvePkceOptions(pkceConfig);
			resolvePkceOptions(pkceConfig, logger);
			expect(logger.warn).toHaveBeenCalledTimes(1);
		});

		it("resolves to the same policy whether or not it warned", () => {
			// The guard must gate the log line and nothing else.
			const pkceConfig = { requireS256: false };
			const first = resolvePkceOptions(pkceConfig);
			const second = resolvePkceOptions(pkceConfig);
			expect(second).toEqual(first);
			expect(second.required).toBe(true);
			expect(second.supportedMethods).toEqual(["S256"]);
		});
	});
});

describe("pkceMethodsForClient (#273)", () => {
	// The policy both endpoints hand in — resolved from config, identical on
	// each side. Taking it as a parameter (rather than closing over the
	// constant) is what makes "/authorize and /token read the same object"
	// checkable rather than asserted.
	const policy = resolvePkceOptions(undefined);

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
