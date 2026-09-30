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
	it("does not re-export the federation adapter port, which core owns", async () => {
		// The port a federation is registered with is core's, the one `oauth`
		// and `federation-grants` read, reachable by that one path so a
		// contribution is typed against the port its readers use.
		const mod = (await import("#/index.mjs")) as Record<string, unknown>;
		for (const name of [
			"supportsDelegatedAuthorization",
			"supportsLogout",
			"supportsRefresh",
			"supportsClaimMapping",
			"identityClaimsProblem",
			"selectIdentityClaims",
			"RESERVED_DELEGATED_AUTHORIZATION_PARAMS",
			"RESERVED_IDENTITY_CLAIMS",
			"resolveFederationResponseMode",
			"FEDERATION_RESPONSE_MODES",
			"DEFAULT_FEDERATION_RESPONSE_MODE",
		]) {
			expect(name in mod).toBe(false);
		}
	});

	it("does not re-export the adapter toolkit, which core owns", async () => {
		// `codeChallenge`, `callbackUrlForExchange` and `resolveClientSecret` are
		// what an adapter builds its requests with, not what this router does:
		// one home, core, and one import path for every adapter.
		const mod = (await import("#/index.mjs")) as Record<string, unknown>;
		for (const name of ["codeChallenge", "callbackUrlForExchange", "resolveClientSecret"]) {
			expect(name in mod).toBe(false);
		}
	});

	it("exports sessionModule as a const Module value (not a factory)", async () => {
		const mod = await import("#/index.mjs");
		const sessionModule = (mod as { sessionModule?: unknown }).sessionModule;
		expect(sessionModule).toBeDefined();
		// sessionModule is a const Module — an object with a `name` field, not a
		// factory function. Asserting object shape (rather than
		// `typeof === "function"`) rules out a factory.
		expect(typeof sessionModule).toBe("object");
		expect((sessionModule as { name: string }).name).toBe("session");
	});

	it("exports establishSession as a function", async () => {
		const mod = (await import("#/index.mjs")) as Record<string, unknown>;
		expect(typeof mod.establishSession).toBe("function");
	});

	it("exports what a composition needs to provide the csrfGuard and loginEntry slots without sessionModule", async () => {
		// device-grant and federation-grants require these slots once enabled; a
		// composition with a login page of its own and no sessionModule builds
		// them with the same functions the module does.
		const mod = (await import("#/index.mjs")) as Record<string, unknown>;
		for (const name of ["createSessionCsrfGuard", "createLoginEntry", "loginEntryFromConfig"]) {
			expect(typeof mod[name], name).toBe("function");
		}
	});

	it("exports what a composition needs to provide the csrfTokenSigner slot without the session store's module", async () => {
		// sessionModule requires the slot; a composition that mounts its own
		// cookie session signs with the session secret as the store's module does.
		const mod = (await import("#/index.mjs")) as {
			createSessionCsrfTokenSigner?: (secret: string) => { sign(payload: string): string };
		};
		// The fixed vector of csrfTokenSigner.test.mts: the store module's signature.
		expect(
			mod
				.createSessionCsrfTokenSigner?.("fixed-vector.session-secret.at-least-32-bytes.ok")
				.sign("4102444800.Zml4ZWQtdmVjdG9yLW5vbmNl"),
		).toBe("uMTD9J4fNg6OrX38rJXZ9QNr3VIPUxlUSG7yRJ3OLkA");
	});

	it("exports loginCompletionModule, which provides the loginCompletion slot alone", async () => {
		const mod = (await import("#/index.mjs")) as Record<string, unknown>;
		const loaded = mod.loginCompletionModule as { name?: unknown; provides?: object } | undefined;
		expect(loaded?.name).toBe("login-completion");
		expect(Object.keys(loaded?.provides ?? {})).toEqual(["loginCompletion"]);
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
	});

	it("does NOT export the standalone validateRedirect helper", async () => {
		const mod = await import("#/index.mjs");
		// Redirect validation exists only as a policy built from an allowlist
		// (`createFederationRedirectPolicy`), which with no allowlist refuses
		// every `redirect_to`, so no permissive shape is exported.
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

	it("exports the transaction and client-secret surface a federation package needs", async () => {
		const mod = (await import("#/index.mjs")) as Record<string, unknown>;
		// A federation package may hand the route layer a computed client secret,
		// and the transaction store is this router's. The response-mode vocabulary
		// it also needs is core's — asserted absent above.
		expect(typeof mod.createFederationTransactionStore).toBe("function");
		expect(typeof mod.deriveFederationTransactionCookieName).toBe("function");
		expect(typeof mod.mintFederationTransactionId).toBe("function");
		// Not on the public surface: what it implemented was a defect.
		expect("applyCrossSiteStateCookie" in mod).toBe(false);
		// The amr marker a federated login records is part of the contract.
		expect((mod as { FEDERATED_AMR?: unknown }).FEDERATED_AMR).toBe("fed");
	});

	it("does NOT export the createFederationProviderFactory federation factory", async () => {
		const mod = await import("#/index.mjs");
		// No createFederationProviderFactory / FederationProviderFactory: federation
		// consumers extend via per-federation defineModule
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

	// The federated claim precedence rule is part of the public surface so
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
