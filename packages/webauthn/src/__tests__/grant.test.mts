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
 * Tests for createWebAuthnGrant — urn:o3co:oauth:grant-type:webauthn handler
 * (spec §2.4 / Wave 1 T30).
 *
 * Strategy:
 *   - verifyWebAuthnAssertion (T25) is vi.mocked — avoids real CBOR/COSE/
 *     crypto; the thin-wrapper contract is tested in internal.verification.test.mts.
 *   - createMemoryWebAuthnCredentialStore (T22/T23) is real — exercises the
 *     full findByCredentialId + updateSignCount (CAS) path.
 *   - ChallengeCeremony is stubbed in-line (simple mock with controllable outcome)
 *     to keep scenarios independent without wiring the full ceremony stack.
 *   - createSymmetricKeyStore (core) is real — issues real JWTs for payload
 *     assertion tests.
 *
 * Cross-refs: Plan T30 / spec §2.4 / PR #172 W1P3 patterns
 */

import {
	type ChallengeCeremony,
	type ChallengeCeremonyOutcome,
	createMemoryWebAuthnCredentialStore,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
	type WebAuthnCredential,
} from "@o3co/auth-provider-core";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

/** Decode a JWT payload without importing jose. */
function decodeJwtPayload(token: string): Record<string, unknown> {
	const parts = token.split(".");
	if (parts.length < 2) throw new Error("invalid jwt");
	return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Mock verifyWebAuthnAssertion before importing the module under test
// ---------------------------------------------------------------------------
vi.mock("../internal/verification.mjs", () => ({
	verifyWebAuthnAssertion: vi.fn(),
	// export the registration function too (unused but must be present for the mock)
	verifyWebAuthnAttestation: vi.fn(),
}));

import { createWebAuthnGrant, WEBAUTHN_GRANT_TYPE } from "../grant.mjs";
import { verifyWebAuthnAssertion } from "../internal/verification.mjs";

const mockVerifyAssertion = vi.mocked(verifyWebAuthnAssertion);

// ---------------------------------------------------------------------------
// Constants + shared fixtures
// ---------------------------------------------------------------------------

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);

const USER_ID = "user-alice-123";
const CREDENTIAL_ID = "dGVzdC1jcmVkZW50aWFsLWlk"; // base64url of "test-credential-id"

/** A minimal WebAuthn AuthenticationResponseJSON stub — shape validated by the
 *  real SimpleWebAuthn call (mocked here). ClientDataJSON encodes a challenge. */
function makeAssertionResponse(challenge = "test-challenge-value"): AuthenticationResponseJSON {
	const clientDataJSON = Buffer.from(
		JSON.stringify({ type: "webauthn.get", challenge, origin: "https://test.example" }),
	).toString("base64url");
	return {
		id: CREDENTIAL_ID,
		rawId: CREDENTIAL_ID,
		response: {
			clientDataJSON,
			authenticatorData: "stub-authdata",
			signature: "stub-signature",
		},
		clientExtensionResults: {},
		type: "public-key",
	};
}

function makeCredential(overrides?: Partial<WebAuthnCredential>): WebAuthnCredential {
	return {
		userId: USER_ID,
		credentialId: CREDENTIAL_ID,
		publicKey: new Uint8Array(64),
		signCount: 5,
		backedUp: false,
		createdAt: new Date("2026-01-01"),
		...overrides,
	};
}

/** Build a minimal GrantDependencies for webauthn grant. */
function makeBaseDeps(
	credentialStore = createMemoryWebAuthnCredentialStore(),
	ceremony: ChallengeCeremony = makeConsumedCeremony(),
): GrantDependencies & {
	webauthnCredentialStore: ReturnType<typeof createMemoryWebAuthnCredentialStore>;
	challengeCeremony: ChallengeCeremony;
	webauthnConfig: { rpId: string; origin: string[] };
} {
	return {
		config: {
			oauth: {
				jwt: { issuer: "https://test.example" },
				accessToken: { expiresIn: 3600 },
				refreshToken: { expiresIn: 86400 },
			},
		} as unknown as GrantDependencies["config"],
		keyStore,
		webauthnCredentialStore: credentialStore,
		challengeCeremony: ceremony,
		webauthnConfig: {
			rpId: "test.example",
			origin: ["https://test.example"],
		},
	} as ReturnType<typeof makeBaseDeps>;
}

/** Build a GrantContext with the given assertion body. */
function makeCtx(
	body: Record<string, unknown> = {},
	authenticatedClient: GrantContext["authenticatedClient"] = null,
): GrantContext {
	return {
		body: {
			grant_type: WEBAUTHN_GRANT_TYPE,
			...body,
		},
		session: {},
		issuer: "https://test.example",
		metadata: {},
		authenticatedClient,
	};
}

// ---------------------------------------------------------------------------
// ChallengeCeremony stubs
// ---------------------------------------------------------------------------

function makeConsumedCeremony(): ChallengeCeremony {
	return {
		consume: vi.fn().mockResolvedValue({ outcome: "consumed" } as ChallengeCeremonyOutcome),
	};
}

function makeCeremonyWithOutcome(outcome: "replayed" | "unknown"): ChallengeCeremony {
	return { consume: vi.fn().mockResolvedValue({ outcome } as ChallengeCeremonyOutcome) };
}

// ---------------------------------------------------------------------------
// WEBAUTHN_GRANT_TYPE constant
// ---------------------------------------------------------------------------

describe("WEBAUTHN_GRANT_TYPE", () => {
	it("is the URN constant", () => {
		expect(WEBAUTHN_GRANT_TYPE).toBe("urn:o3co:oauth:grant-type:webauthn");
	});
});

// ---------------------------------------------------------------------------
// Assertion parsing
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — assertion parsing", () => {
	beforeEach(() => vi.clearAllMocks());

	it("returns 400 invalid_grant when assertion is missing", async () => {
		const handler = createWebAuthnGrant(makeBaseDeps());
		const { result } = await handler.handle(makeCtx({}));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});

	it("returns 400 invalid_grant when assertion is not an object", async () => {
		const handler = createWebAuthnGrant(makeBaseDeps());
		const { result } = await handler.handle(makeCtx({ assertion: "not-an-object" }));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});

	it("returns 400 invalid_grant when assertion.id is missing", async () => {
		const handler = createWebAuthnGrant(makeBaseDeps());
		const { result } = await handler.handle(makeCtx({ assertion: { type: "public-key" } }));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});

	it("returns 400 invalid_grant when assertion.response.clientDataJSON is not a valid base64url JSON", async () => {
		const handler = createWebAuthnGrant(makeBaseDeps());
		const { result } = await handler.handle(
			makeCtx({
				assertion: {
					id: CREDENTIAL_ID,
					rawId: CREDENTIAL_ID,
					response: { clientDataJSON: "!!!not-base64url!!!" },
					type: "public-key",
					clientExtensionResults: {},
				},
			}),
		);

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});
});

// ---------------------------------------------------------------------------
// Credential lookup
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — credential lookup", () => {
	beforeEach(() => vi.clearAllMocks());

	it("returns 400 invalid_grant when credentialId is not found in the store", async () => {
		// Empty store — credential not registered
		const deps = makeBaseDeps();
		const handler = createWebAuthnGrant(deps);

		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(makeCtx({ assertion }));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});
});

// ---------------------------------------------------------------------------
// Challenge ceremony
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — challenge ceremony", () => {
	beforeEach(() => vi.clearAllMocks());

	it("returns 400 invalid_grant when challenge outcome is 'replayed'", async () => {
		const store = createMemoryWebAuthnCredentialStore();
		await store.put(makeCredential());

		// Assertion verification succeeds (ceremony checked before verify call, so
		// this path should not even reach verify — but mock to avoid stray failures)
		mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });

		const deps = makeBaseDeps(store, makeCeremonyWithOutcome("replayed"));
		const handler = createWebAuthnGrant(deps);

		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(makeCtx({ assertion }));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});

	it("returns 400 invalid_grant when challenge outcome is 'unknown'", async () => {
		const store = createMemoryWebAuthnCredentialStore();
		await store.put(makeCredential());

		mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });

		const deps = makeBaseDeps(store, makeCeremonyWithOutcome("unknown"));
		const handler = createWebAuthnGrant(deps);

		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(makeCtx({ assertion }));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});
});

// ---------------------------------------------------------------------------
// Assertion verification
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — assertion verification", () => {
	beforeEach(() => vi.clearAllMocks());

	it("returns 400 invalid_grant when assertion verification fails (signature_invalid)", async () => {
		const store = createMemoryWebAuthnCredentialStore();
		await store.put(makeCredential());

		mockVerifyAssertion.mockResolvedValue({ ok: false, reason: "signature_invalid" });

		const deps = makeBaseDeps(store);
		const handler = createWebAuthnGrant(deps);

		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(makeCtx({ assertion }));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
		expect("errorDescription" in result && result.errorDescription).toContain("signature_invalid");
	});

	it("returns 400 invalid_grant when assertion verification fails (sign_count_regression)", async () => {
		const store = createMemoryWebAuthnCredentialStore();
		await store.put(makeCredential());

		mockVerifyAssertion.mockResolvedValue({ ok: false, reason: "sign_count_regression" });

		const deps = makeBaseDeps(store);
		const handler = createWebAuthnGrant(deps);

		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(makeCtx({ assertion }));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
		expect("errorDescription" in result && result.errorDescription).toContain(
			"sign_count_regression",
		);
	});
});

// ---------------------------------------------------------------------------
// CAS sign-count update
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — CAS sign-count update", () => {
	beforeEach(() => vi.clearAllMocks());

	it("returns 400 invalid_grant when updateSignCount returns false (concurrent race)", async () => {
		const store = createMemoryWebAuthnCredentialStore();
		await store.put(makeCredential({ signCount: 5 }));

		// Simulate another request winning the CAS by stubbing updateSignCount to
		// always return false (lost race / stored signCount already advanced).
		const updateSpy = vi
			.spyOn(store, "updateSignCount")
			.mockImplementation(async (_credentialId, _args) => false);

		mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });

		const deps = makeBaseDeps(store);
		const handler = createWebAuthnGrant(deps);

		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(makeCtx({ assertion }));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
		updateSpy.mockRestore();
	});
});

// ---------------------------------------------------------------------------
// Success path
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — success (Wave 1 first slice)", () => {
	beforeEach(() => vi.clearAllMocks());

	it("issues access_token with sub=credential.userId and no refresh_token", async () => {
		const store = createMemoryWebAuthnCredentialStore();
		await store.put(makeCredential());

		mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });

		const deps = makeBaseDeps(store);
		const handler = createWebAuthnGrant(deps);

		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(makeCtx({ assertion }));

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");

		const { tokens } = result;
		expect(tokens.access_token).toBeTruthy();
		// Wave 1 §2.4: no refresh token
		expect(tokens.refresh_token).toBeUndefined();

		const payload = decodeJwtPayload(tokens.access_token) as Record<string, unknown>;
		expect(payload.sub).toBe(USER_ID);
	});

	it("updates the stored signCount after successful verification", async () => {
		const store = createMemoryWebAuthnCredentialStore();
		await store.put(makeCredential({ signCount: 5 }));

		mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });

		const deps = makeBaseDeps(store);
		const handler = createWebAuthnGrant(deps);

		const assertion = makeAssertionResponse();
		await handler.handle(makeCtx({ assertion }));

		const updated = await store.findByCredentialId(CREDENTIAL_ID);
		expect(updated?.signCount).toBe(6);
	});

	it("uses issuer as aud when no authenticated client is present", async () => {
		const store = createMemoryWebAuthnCredentialStore();
		await store.put(makeCredential());

		mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });

		const deps = makeBaseDeps(store);
		const handler = createWebAuthnGrant(deps);

		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(makeCtx({ assertion }, null));

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		const payload = decodeJwtPayload(result.tokens.access_token);
		expect(payload.aud).toBe("https://test.example");
	});

	it("uses client.allowedAudiences[0] when an authenticated client is present", async () => {
		const store = createMemoryWebAuthnCredentialStore();
		await store.put(makeCredential());

		mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });

		const deps = makeBaseDeps(store);
		const handler = createWebAuthnGrant(deps);

		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(
			makeCtx(
				{ assertion },
				{
					clientId: "my-app",
					tokenEndpointAuthMethod: "none",
					allowedAudiences: ["https://rs.example"],
				},
			),
		);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		const payload = decodeJwtPayload(result.tokens.access_token);
		expect(payload.aud).toBe("https://rs.example");
	});
});

// ---------------------------------------------------------------------------
// RFC 8707 resource indicator (flag gating)
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — RFC 8707 resource indicator gating", () => {
	beforeEach(() => vi.clearAllMocks());

	it("flag-off: body.resource present but policy sees resource: undefined", async () => {
		const store = createMemoryWebAuthnCredentialStore();
		await store.put(makeCredential());

		mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });

		const evaluateSpy = vi.fn().mockResolvedValue({ outcome: "allow" });
		const depsWithPolicy = {
			...makeBaseDeps(store),
			config: {
				oauth: {
					jwt: { issuer: "https://test.example" },
					accessToken: { expiresIn: 3600 },
					refreshToken: { expiresIn: 86400 },
					// resourceIndicator absent = flag-off
				},
			} as unknown as GrantDependencies["config"],
			grantPolicy: {
				kind: "test",
				evaluate: evaluateSpy,
			},
		};

		const handler = createWebAuthnGrant(depsWithPolicy);
		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(
			makeCtx({ assertion, resource: "https://rs1.example" }),
		);

		// Policy should NOT be called because resourceIndicator is off
		expect(evaluateSpy).not.toHaveBeenCalled();
		expect(result.status).toBe(200);
	});

	it("flag-on: body.resource is forwarded to policy", async () => {
		const store = createMemoryWebAuthnCredentialStore();
		await store.put(makeCredential());

		mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });

		const evaluateSpy = vi.fn().mockResolvedValue({ outcome: "allow" });
		const depsWithPolicy = {
			...makeBaseDeps(store),
			config: {
				oauth: {
					jwt: { issuer: "https://test.example" },
					accessToken: { expiresIn: 3600 },
					refreshToken: { expiresIn: 86400 },
					resourceIndicator: { enabled: true },
				},
			} as unknown as GrantDependencies["config"],
			grantPolicy: {
				kind: "test",
				evaluate: evaluateSpy,
			},
		};

		const handler = createWebAuthnGrant(depsWithPolicy);
		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(
			makeCtx({ assertion, resource: "https://rs1.example" }),
		);

		expect(evaluateSpy).toHaveBeenCalledOnce();
		const [req] = evaluateSpy.mock.calls[0];
		expect(req.resource).toEqual(["https://rs1.example"]);
		expect(result.status).toBe(200);
	});
});

// ---------------------------------------------------------------------------
// grantPolicy — deny, scope ceiling, audience, fail-closed (CP-18)
// ---------------------------------------------------------------------------

describe("createWebAuthnGrant — grantPolicy (CP-18 fail-closed)", () => {
	beforeEach(() => vi.clearAllMocks());

	function makeDepsWith(
		evaluateFn: (...args: unknown[]) => Promise<{
			outcome: "allow" | "deny";
			grantedScope?: string[];
			grantedAudience?: string[];
			error?: string;
			errorDescription?: string;
		}>,
	) {
		const store = createMemoryWebAuthnCredentialStore();
		return {
			store,
			deps: {
				...makeBaseDeps(store),
				config: {
					oauth: {
						jwt: { issuer: "https://test.example" },
						accessToken: { expiresIn: 3600 },
						refreshToken: { expiresIn: 86400 },
						resourceIndicator: { enabled: true },
					},
				} as unknown as GrantDependencies["config"],
				grantPolicy: {
					kind: "test",
					evaluate: evaluateFn as unknown as GrantDependencies["grantPolicy"],
				} as unknown as GrantDependencies["grantPolicy"],
			},
		};
	}

	it("returns 400 with policy error when policy denies", async () => {
		const { store, deps } = makeDepsWith(async () => ({
			outcome: "deny",
			error: "access_denied",
			errorDescription: "policy denied",
		}));
		await store.put(makeCredential());
		mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });

		const handler = createWebAuthnGrant(deps);
		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(makeCtx({ assertion, resource: "https://rs1" }));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("access_denied");
	});

	it("returns 503 temporarily_unavailable when policy throws (CP-18 fail-closed)", async () => {
		const { store, deps } = makeDepsWith(async () => {
			throw new Error("policy service down");
		});
		await store.put(makeCredential());
		mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });

		const handler = createWebAuthnGrant(deps);
		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(makeCtx({ assertion, resource: "https://rs1" }));

		expect(result.status).toBe(503);
		expect("error" in result && result.error).toBe("temporarily_unavailable");
	});

	it("returns 400 invalid_scope when policy grantedScope exceeds effectiveScopes ceiling (Codex P1-1 pattern)", async () => {
		// Requested scope: "read". Policy returns ["write"]. write ∉ effectiveScopes → fail-closed.
		const { store, deps } = makeDepsWith(async () => ({
			outcome: "allow",
			grantedScope: ["write"],
		}));
		await store.put(makeCredential());
		mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });

		const handler = createWebAuthnGrant(deps);
		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(
			makeCtx({ assertion, resource: "https://rs1", scope: "read" }),
		);

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_scope");
		expect("errorDescription" in result && result.errorDescription).toContain("write");
	});

	it("honors empty grantedScope: [] from policy (strip-all — Codex P1-2 pattern)", async () => {
		const { store, deps } = makeDepsWith(async () => ({
			outcome: "allow",
			grantedScope: [],
		}));
		await store.put(makeCredential());
		mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });

		const handler = createWebAuthnGrant(deps);
		const assertion = makeAssertionResponse();
		const { result } = await handler.handle(
			makeCtx({ assertion, resource: "https://rs1", scope: "read" }),
		);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens");
		const payload = decodeJwtPayload(result.tokens.access_token) as Record<string, unknown>;
		// scope claim absent or empty when policy strips all
		expect(payload.scope ?? "").toBe("");
	});

	it("returns 400 invalid_request when policy grantedAudience exceeds client.allowedAudiences", async () => {
		const { store, deps } = makeDepsWith(async () => ({
			outcome: "allow",
			grantedAudience: ["https://rogue.example"],
		}));
		await store.put(makeCredential());
		mockVerifyAssertion.mockResolvedValue({ ok: true, newSignCount: 6 });

		const handler = createWebAuthnGrant(deps);
		const assertion = makeAssertionResponse();
		// Provide an authenticated client with allowedAudiences
		const { result } = await handler.handle(
			makeCtx(
				{ assertion, resource: "https://rs1" },
				{
					clientId: "app",
					tokenEndpointAuthMethod: "none",
					allowedAudiences: ["https://rs1.example"],
				},
			),
		);

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_request");
		expect("errorDescription" in result && result.errorDescription).toContain(
			"https://rogue.example",
		);
	});
});
