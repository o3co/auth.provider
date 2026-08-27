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

describe("package public surface (@o3co/auth-provider-session)", () => {
	it("exports supportsLogout as a runtime helper", async () => {
		const mod = await import("#/index.mjs");
		expect(typeof (mod as { supportsLogout?: unknown }).supportsLogout).toBe("function");
	});

	it("exports sessionModule as a const Module value (not a factory)", async () => {
		const mod = await import("#/index.mjs");
		const sessionModule = (mod as { sessionModule?: unknown }).sessionModule;
		expect(sessionModule).toBeDefined();
		// Per A2-γ §3.4: sessionModule is now a const Module — an object with a
		// `name` field, not a factory function. Asserting object shape (rather
		// than `typeof === "function"`) pins the v0.5.0 surface against the
		// deleted v0.4.x factory shape.
		expect(typeof sessionModule).toBe("object");
		expect((sessionModule as { name: string }).name).toBe("session");
	});

	it("exports extractFederationSection as a runtime helper", async () => {
		const mod = await import("#/index.mjs");
		expect(typeof (mod as { extractFederationSection?: unknown }).extractFederationSection).toBe(
			"function",
		);
	});

	it("exports federation helper utilities for provider packages", async () => {
		const mod = await import("#/index.mjs");
		expect(typeof (mod as { resolveCallbackRedirect?: unknown }).resolveCallbackRedirect).toBe(
			"function",
		);
		expect(typeof (mod as { codeChallenge?: unknown }).codeChallenge).toBe("function");
	});

	it("does NOT export the standalone validateRedirect helper (#278)", async () => {
		const mod = await import("#/index.mjs");
		// It derived its answer from `sessionDomain` alone and accepted every
		// http(s) URL when that was unset — an open redirect for any consumer
		// wiring it directly. Redirect validation now exists only as a policy
		// built from an allowlist, so there is no permissive shape left to reach.
		expect((mod as Record<string, unknown>).validateRedirect).toBeUndefined();
	});

	it("exports the redirect-policy rules a custom policy needs to match", async () => {
		const mod = await import("#/index.mjs");
		expect(
			typeof (mod as { createFederationRedirectPolicy?: unknown }).createFederationRedirectPolicy,
		).toBe("function");
		expect(typeof (mod as { describeRedirectRejection?: unknown }).describeRedirectRejection).toBe(
			"function",
		);
		expect(typeof (mod as { isLoopbackHostname?: unknown }).isLoopbackHostname).toBe("function");
		expect((mod as { MAX_REDIRECT_URL_LENGTH?: unknown }).MAX_REDIRECT_URL_LENGTH).toBe(2048);
	});

	it("does NOT export the deleted v0.4.x federation factory surface", async () => {
		const mod = await import("#/index.mjs");
		// Per A2-γ §3.4 + Phase 9 issue #98 full removal:
		// createFederationProviderFactory and FederationProviderFactory are deleted.
		// Federation consumers now extend via per-federation defineModule
		// (see federation-google / federation-github).
		expect((mod as Record<string, unknown>).createFederationProviderFactory).toBeUndefined();
	});

	it("does NOT export concrete Google/GitHub provider factories", async () => {
		const mod = await import("#/index.mjs");
		expect((mod as Record<string, unknown>).createGoogleProvider).toBeUndefined();
		expect((mod as Record<string, unknown>).createGithubProvider).toBeUndefined();
		expect((mod as Record<string, unknown>).registerBuiltinFederations).toBeUndefined();
	});

	it("does NOT export createPassport (passport-era export removed)", async () => {
		const mod = await import("#/index.mjs");
		expect((mod as Record<string, unknown>).createPassport).toBeUndefined();
	});

	it("does not export removed type-only names as runtime values", async () => {
		const mod = await import("#/index.mjs");
		expect((mod as Record<string, unknown>).VerifyUserContext).toBeUndefined();
	});

	it("does NOT export SetupPassportContext (passport-era type removed)", async () => {
		const mod = await import("#/index.mjs");
		expect((mod as Record<string, unknown>).SetupPassportContext).toBeUndefined();
	});

	// #279 — the federated claim precedence rule is part of the public surface so
	// a deployment can assert on it (and on the promotable set) from its own tests.
	it("exports the federated claim precedence surface", async () => {
		const mod = await import("#/index.mjs");
		expect(typeof (mod as { mergeFederatedClaims?: unknown }).mergeFederatedClaims).toBe(
			"function",
		);
		expect((mod as { FEDERATED_CLAIMS_KEY?: unknown }).FEDERATED_CLAIMS_KEY).toBe("federated");
		expect((mod as { PROMOTABLE_FEDERATED_CLAIMS?: unknown }).PROMOTABLE_FEDERATED_CLAIMS).toEqual([
			"email",
			"name",
			"picture",
		]);
	});
});
