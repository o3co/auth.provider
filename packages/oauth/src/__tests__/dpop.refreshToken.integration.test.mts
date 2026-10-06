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
 * The DPoP refresh-token binding matrix: how the refresh_token grant
 * correlates the RT's persisted `cnf.jkt` claim with the request-time DPoP
 * proof presented via `ctx.tokenBinding`:
 *
 *   | RT cnf.jkt | proof JKT       | Outcome
 *   | no         | no              | row 1: issue plain Bearer
 *   | no         | yes             | row 2: opt-in upgrade — bind new AT (RT bound only for public)
 *   | yes        | no              | row 3: reject invalid_grant "requires a DPoP proof"
 *   | yes        | yes, differs    | row 4: reject invalid_grant "does not match refresh_token binding"
 *   | yes        | yes, equal      | row 5: rotation preserves binding (AT + RT for public)
 *
 * Drives the grant handler directly (as refreshToken.test.mts does), with RTs
 * minted via SignJWT carrying arbitrary cnf claims. The matrix runs BEFORE
 * rotation, so the deps carry no refreshTokenFamilyRotation.
 */

import { createSecretKey } from "node:crypto";
import {
	createSymmetricKeyStore,
	type GrantContext,
	type TokenBinding,
} from "@o3co/auth-provider-core";
import { createTestTokenBindingSettings, resolverForTests } from "@o3co/auth-provider-core/testing";
import { decodeJwt, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createRefreshTokenGrant, type RefreshTokenGrantDeps } from "#/grants/refreshToken.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { grantSettingsFrom } from "./_helpers/grantSettings.mjs";
import {
	COMPOUND_DPOP_BINDING,
	COMPOUND_MTLS_BINDING,
	UNOWNED_BINDINGS,
} from "./_helpers/unownedBindings.mjs";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const CONFIDENTIAL_CLIENT_ID = "rt-confidential-client";
const PUBLIC_CLIENT_ID = "rt-public-client";

const mockConfig = {
	oauth: {
		jwt: { secret: SECRET },
		accessToken: { defaultExpiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {
			refresh_token: { enabled: true },
		},
	},
};

const mockDeps: RefreshTokenGrantDeps = {
	...grantSettingsFrom(mockConfig),
	keyStore,
	sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
};

/** `mockDeps` with core's opt-in `bindConfidentialClientRefreshTokens` set in its slot. */
const depsWithConfidentialBinding = (enabled: boolean): RefreshTokenGrantDeps => ({
	...mockDeps,
	tokenBindingSettings: createTestTokenBindingSettings({
		bindConfidentialClientRefreshTokens: enabled,
	}),
});

const confidentialAuthClient = {
	clientId: CONFIDENTIAL_CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
};

const publicAuthClient = {
	clientId: PUBLIC_CLIENT_ID,
	tokenEndpointAuthMethod: "none" as const,
};

// ---------------------------------------------------------------------------
// RT minter — produces signed JWTs with optional cnf claim
// ---------------------------------------------------------------------------

interface MintRtOptions {
	readonly clientId: string;
	readonly cnfJkt?: string;
	readonly sub?: string;
	readonly scope?: string;
}

async function mintRefreshToken(opts: MintRtOptions): Promise<string> {
	const payload: Record<string, unknown> = {
		sub: opts.sub ?? "u1",
		scope: opts.scope ?? "read write",
	};
	if (opts.cnfJkt !== undefined) {
		payload.cnf = { jkt: opts.cnfJkt };
	}
	return new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setIssuer("localhost")
		.setAudience(opts.clientId)
		.setExpirationTime("24h")
		.sign(secretKey);
}

// ---------------------------------------------------------------------------
// ctx builders
// ---------------------------------------------------------------------------

function buildCtx(opts: {
	readonly refreshToken: string;
	readonly authenticatedClient: typeof confidentialAuthClient | typeof publicAuthClient;
	readonly tokenBinding?: TokenBinding;
}): GrantContext {
	const ctx: GrantContext = {
		body: { refresh_token: opts.refreshToken },
		session: {},
		issuer: "localhost",
		metadata: { ip: "127.0.0.1" },
		authenticatedClient: opts.authenticatedClient,
	};
	if (opts.tokenBinding) {
		(ctx as { tokenBinding?: TokenBinding }).tokenBinding = opts.tokenBinding;
	}
	return ctx;
}

const dpopBinding = (jkt: string): TokenBinding => ({
	kind: "dpop",
	confirmation: { jkt },
});

// ---------------------------------------------------------------------------
// 5-row matrix tests
// ---------------------------------------------------------------------------

describe("DPoP refresh-token binding matrix (5 rows)", () => {
	it("row 1: RT plain + no proof → unbound AT, Bearer", async () => {
		// An RT never bound, no proof presented: the grant MUST keep issuing
		// Bearer only — binding is opt-in.
		const rt = await mintRefreshToken({ clientId: CONFIDENTIAL_CLIENT_ID });
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: confidentialAuthClient,
		});

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		expect(result.tokens.token_type).toBe("Bearer");
		const atPayload = decodeJwt(result.tokens.access_token);
		expect(atPayload.cnf).toBeUndefined();
		// New RT also unbound (no proof to copy from)
		expect(result.tokens.refresh_token).toBeTruthy();
		const newRtPayload = decodeJwt(result.tokens.refresh_token as string);
		expect(newRtPayload.cnf).toBeUndefined();
	});

	it("row 2: RT plain + proof → opt-in upgrade, AT bound, RT bound only for public client", async () => {
		// Public client opt-in upgrade — proof presented for an unbound RT. Per
		// the public-client gate, the new RT MUST also be bound so a subsequent
		// refresh enforces continuity. Confidential clients in row 2 get
		// AT-bound but RT-plain (next sub-test).
		const rt = await mintRefreshToken({ clientId: PUBLIC_CLIENT_ID });
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: publicAuthClient,
			tokenBinding: dpopBinding("PROOF-JKT"),
		});

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		expect(result.tokens.token_type).toBe("DPoP");
		const atPayload = decodeJwt(result.tokens.access_token);
		expect((atPayload.cnf as { jkt?: string } | undefined)?.jkt).toBe("PROOF-JKT");
		// Public client → new RT MUST also carry cnf for cross-refresh continuity
		expect(result.tokens.refresh_token).toBeTruthy();
		const newRtPayload = decodeJwt(result.tokens.refresh_token as string);
		expect((newRtPayload.cnf as { jkt?: string } | undefined)?.jkt).toBe("PROOF-JKT");
	});

	it("row 2 (confidential variant): RT plain + proof → AT bound, RT remains plain", async () => {
		// Confidential clients have the client secret as the refresh-time
		// authenticator (RFC 9449 §5). RT-key-binding adds no security and would
		// force the client to retain the DPoP key across the RT lifetime.
		const rt = await mintRefreshToken({ clientId: CONFIDENTIAL_CLIENT_ID });
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: confidentialAuthClient,
			tokenBinding: dpopBinding("PROOF-JKT-CONF"),
		});

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		expect(result.tokens.token_type).toBe("DPoP");
		const atPayload = decodeJwt(result.tokens.access_token);
		expect((atPayload.cnf as { jkt?: string } | undefined)?.jkt).toBe("PROOF-JKT-CONF");
		// Confidential client → new RT MUST remain plain
		expect(result.tokens.refresh_token).toBeTruthy();
		const newRtPayload = decodeJwt(result.tokens.refresh_token as string);
		expect(newRtPayload.cnf).toBeUndefined();
	});

	it("row 3: RT bound + no proof → reject invalid_grant", async () => {
		// The RT itself promised DPoP binding (carries cnf.jkt). A subsequent
		// refresh without proof would let an attacker who exfiltrated the RT
		// use it freely — the entire point of binding is broken. Hard reject.
		const rt = await mintRefreshToken({
			clientId: PUBLIC_CLIENT_ID,
			cnfJkt: "RT-PROMISED-JKT",
		});
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: publicAuthClient,
			// No tokenBinding — proof absent
		});

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(400);
		if (!("error" in result)) expect.fail("Expected error in result");
		expect(result.error).toBe("invalid_grant");
		expect(result.errorDescription).toContain("requires a DPoP proof");
	});

	it("row 4: RT bound + proof mismatch → reject invalid_grant (multi-key attack)", async () => {
		// Multi-key attack vector: attacker has stolen the RT but uses their own
		// DPoP key to mint a proof. The thumbprint comparison MUST catch this
		// even though the proof JWT itself is structurally valid.
		const rt = await mintRefreshToken({
			clientId: PUBLIC_CLIENT_ID,
			cnfJkt: "RT-PROMISED-JKT",
		});
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: publicAuthClient,
			tokenBinding: dpopBinding("ATTACKER-JKT"),
		});

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(400);
		if (!("error" in result)) expect.fail("Expected error in result");
		expect(result.error).toBe("invalid_grant");
		expect(result.errorDescription).toContain("does not match refresh_token binding");
	});

	it("row 5: RT bound + proof match → rotation preserves binding (public client)", async () => {
		// Happy path for an already-bound public-client RT: the proof's JKT
		// equals the persisted cnf.jkt. New AT inherits the binding, new RT
		// also carries it so the next refresh enforces continuity.
		const rt = await mintRefreshToken({
			clientId: PUBLIC_CLIENT_ID,
			cnfJkt: "MATCH-JKT",
		});
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: publicAuthClient,
			tokenBinding: dpopBinding("MATCH-JKT"),
		});

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		expect(result.tokens.token_type).toBe("DPoP");
		const atPayload = decodeJwt(result.tokens.access_token);
		expect((atPayload.cnf as { jkt?: string } | undefined)?.jkt).toBe("MATCH-JKT");
		expect(result.tokens.refresh_token).toBeTruthy();
		const newRtPayload = decodeJwt(result.tokens.refresh_token as string);
		expect((newRtPayload.cnf as { jkt?: string } | undefined)?.jkt).toBe("MATCH-JKT");
	});
});

// ---------------------------------------------------------------------------
// Mechanism boundaries
// ---------------------------------------------------------------------------

describe("DPoP refresh-token mechanism boundary", () => {
	it("non-DPoP mechanism emitting cnf.jkt cannot satisfy a DPoP-bound RT", async () => {
		// The Confirmation union is mechanism-extensible — a custom mechanism
		// (e.g. a FIDO attestation binding) could emit `{ jkt: "..." }`
		// without being DPoP. The matrix's proof extraction MUST gate on
		// `kind === "dpop"` so a non-DPoP mechanism cannot satisfy a
		// DPoP-bound RT just by reusing the jkt confirmation shape.
		const rt = await mintRefreshToken({
			clientId: PUBLIC_CLIENT_ID,
			cnfJkt: "RT-DPOP-BOUND-JKT",
		});
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: publicAuthClient,
			tokenBinding: {
				// Hypothetical non-DPoP mechanism emitting a jkt-shaped cnf.
				// `as TokenBinding` is required because "fido" isn't a known
				// kind value, but the type system allows downstream
				// mechanism authors to extend `kind` via string union.
				kind: "fido",
				confirmation: { jkt: "RT-DPOP-BOUND-JKT" },
			} as TokenBinding,
		});

		const { result } = await handler.handle(ctx);

		// MUST reject as row 3 (RT bound, proof absent for DPoP purposes)
		// rather than passing the matrix on jkt structural match. The kind
		// boundary is enforced structurally — not by convention.
		expect(result.status).toBe(400);
		if (!("error" in result)) expect.fail("Expected error in result");
		expect(result.error).toBe("invalid_grant");
		expect(result.errorDescription).toContain("requires a DPoP proof");
	});

	it("mTLS public-client row 2 (RT plain + cert) → opt-in upgrade, new RT bound with x5t#S256 (RFC 8705 §4)", async () => {
		// The refresh-time matrix covers mTLS too, so a public-client mTLS
		// refresh MUST emit a bound RT to enforce cross-refresh continuity
		// (parallel to DPoP row 2, public variant). Confidential clients get
		// RT-plain: the public-client gate covers both mechanisms.
		const rt = await mintRefreshToken({ clientId: PUBLIC_CLIENT_ID });
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: publicAuthClient,
			tokenBinding: {
				kind: "mtls",
				confirmation: { "x5t#S256": "MTLS-RT-THUMB" },
			},
		});

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		// mTLS keeps Bearer per RFC 8705 §3.
		expect(result.tokens.token_type).toBe("Bearer");
		// AT gets the member the mTLS mechanism owns (core's `ownedConfirmation`).
		const atPayload = decodeJwt(result.tokens.access_token);
		expect((atPayload.cnf as { "x5t#S256"?: string } | undefined)?.["x5t#S256"]).toBe(
			"MTLS-RT-THUMB",
		);
		// Public client + mTLS → new RT MUST carry cnf.x5t#S256 (RFC 8705 §4).
		expect(result.tokens.refresh_token).toBeTruthy();
		const newRtPayload = decodeJwt(result.tokens.refresh_token as string);
		expect((newRtPayload.cnf as { "x5t#S256"?: string } | undefined)?.["x5t#S256"]).toBe(
			"MTLS-RT-THUMB",
		);
	});
});

// ---------------------------------------------------------------------------
// Opt-in RT binding for confidential clients
// ---------------------------------------------------------------------------

/*
 * Neither RFC requires this, and neither forbids it. RFC 9449 §5 ("Refresh
 * tokens issued to confidential clients ... are not bound to the DPoP proof
 * public key because they are already sender-constrained with a different
 * existing mechanism") is descriptive prose with no RFC 2119 keyword; RFC 8705
 * §7.1 says the same for certificates ("indirectly certificate-bound by way of
 * the client ID and the associated requirement for (certificate-based)
 * authentication").
 *
 * This grant refuses an unauthenticated caller and an RT whose `azp` is not
 * the authenticated client, so a stolen RT is unusable without the client's
 * credential. Binding helps only where the two credentials are protected
 * differently (a client secret in an environment variable, a DPoP key in an
 * HSM or TPM). It is off by default: a bound RT pins the client to one key or
 * certificate for the RT's whole lifetime, so a mid-lifetime key rotation
 * breaks refresh.
 *
 * The flag is mechanism-neutral because the gate it modifies
 * (`(bindingIsDpop || bindingIsMtls) && isPublicClient`) is, and
 * `oauth.tokenBinding` is where cross-mechanism policy lives.
 */
describe("confidential-client RT binding — opt-in", () => {
	it("is off by default: a confidential client's new RT stays plain", async () => {
		const rt = await mintRefreshToken({ clientId: CONFIDENTIAL_CLIENT_ID });
		const { result } = await createRefreshTokenGrant(mockDeps).handle(
			buildCtx({
				refreshToken: rt,
				authenticatedClient: confidentialAuthClient,
				tokenBinding: dpopBinding("PROOF-JKT-CONF"),
			}),
		);
		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		expect(decodeJwt(result.tokens.refresh_token as string).cnf).toBeUndefined();
	});

	it("stays off when the key is present and false", async () => {
		const rt = await mintRefreshToken({ clientId: CONFIDENTIAL_CLIENT_ID });
		const { result } = await createRefreshTokenGrant(depsWithConfidentialBinding(false)).handle(
			buildCtx({
				refreshToken: rt,
				authenticatedClient: confidentialAuthClient,
				tokenBinding: dpopBinding("PROOF-JKT-CONF"),
			}),
		);
		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		expect(decodeJwt(result.tokens.refresh_token as string).cnf).toBeUndefined();
	});

	it("binds a confidential client's new RT when turned on", async () => {
		const rt = await mintRefreshToken({ clientId: CONFIDENTIAL_CLIENT_ID });
		const { result } = await createRefreshTokenGrant(depsWithConfidentialBinding(true)).handle(
			buildCtx({
				refreshToken: rt,
				authenticatedClient: confidentialAuthClient,
				tokenBinding: dpopBinding("PROOF-JKT-CONF"),
			}),
		);
		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		const newRt = decodeJwt(result.tokens.refresh_token as string);
		expect((newRt.cnf as { jkt?: string } | undefined)?.jkt).toBe("PROOF-JKT-CONF");
	});

	// The continuity matrix is what makes the binding mean anything, and it
	// already runs off the RT's own cnf — so turning the flag on enrolls
	// confidential clients in it with no second rule to keep in step.
	it("enforces continuity on the RT it just bound", async () => {
		const rt = await mintRefreshToken({
			clientId: CONFIDENTIAL_CLIENT_ID,
			cnfJkt: "PROOF-JKT-CONF",
		});
		const { result } = await createRefreshTokenGrant(depsWithConfidentialBinding(true)).handle(
			buildCtx({
				refreshToken: rt,
				authenticatedClient: confidentialAuthClient,
				tokenBinding: dpopBinding("A-DIFFERENT-KEY"),
			}),
		);
		expect(result.status).toBe(400);
		if ("tokens" in result) expect.fail("Expected a rejection");
		expect(result.error).toBe("invalid_grant");
	});

	it("binds exactly when core's tokenBindingSettings slot says so: the setting is core's", async () => {
		for (const tokenBindingSettings of [
			createTestTokenBindingSettings(),
			createTestTokenBindingSettings({ bindConfidentialClientRefreshTokens: true }),
			createTestTokenBindingSettings({ bindConfidentialClientRefreshTokens: false }),
			createTestTokenBindingSettings({
				dispatchPolicy: "strict-mutual-exclusion",
				bindConfidentialClientRefreshTokens: true,
			}),
		]) {
			const rt = await mintRefreshToken({ clientId: CONFIDENTIAL_CLIENT_ID });
			const { result } = await createRefreshTokenGrant({
				...mockDeps,
				tokenBindingSettings,
			}).handle(
				buildCtx({
					refreshToken: rt,
					authenticatedClient: confidentialAuthClient,
					tokenBinding: dpopBinding("PROOF-JKT-CONF"),
				}),
			);
			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");
			const bound = decodeJwt(result.tokens.refresh_token as string).cnf !== undefined;
			expect(bound, JSON.stringify(tokenBindingSettings)).toBe(
				tokenBindingSettings.bindConfidentialClientRefreshTokens,
			);
		}
	});

	// A public client was already bound; the flag must not reach it.
	it("binds a public client's new RT to the proof with the flag unset or off", async () => {
		const rt = await mintRefreshToken({ clientId: PUBLIC_CLIENT_ID });
		for (const deps of [mockDeps, depsWithConfidentialBinding(false)]) {
			const { result } = await createRefreshTokenGrant(deps).handle(
				buildCtx({
					refreshToken: rt,
					authenticatedClient: publicAuthClient,
					tokenBinding: dpopBinding("PROOF-JKT-PUB"),
				}),
			);
			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");
			const newRt = decodeJwt(result.tokens.refresh_token as string);
			expect((newRt.cnf as { jkt?: string } | undefined)?.jkt).toBe("PROOF-JKT-PUB");
		}
	});
});

describe("refresh_token stamps only the confirmation the binding's mechanism owns", () => {
	// A plain refresh token and a public client: row 2's opt-in upgrade, where
	// the presented binding is what both new tokens would be bound to.
	it.each(UNOWNED_BINDINGS)(
		"mints an unbound access and refresh token, advertised as Bearer, for %s",
		async (_label, tokenBinding) => {
			const rt = await mintRefreshToken({ clientId: PUBLIC_CLIENT_ID });
			const { result } = await createRefreshTokenGrant(mockDeps).handle(
				buildCtx({ refreshToken: rt, authenticatedClient: publicAuthClient, tokenBinding }),
			);

			expect(result.status).toBe(200);
			if (!("tokens" in result)) expect.fail("Expected tokens in result");
			expect(decodeJwt(result.tokens.access_token).cnf).toBeUndefined();
			expect(decodeJwt(result.tokens.refresh_token as string).cnf).toBeUndefined();
			expect(result.tokens.token_type).toBe("Bearer");
		},
	);

	it("stamps the DPoP member of a compound confirmation and nothing else", async () => {
		const rt = await mintRefreshToken({ clientId: PUBLIC_CLIENT_ID });
		const { result } = await createRefreshTokenGrant(mockDeps).handle(
			buildCtx({
				refreshToken: rt,
				authenticatedClient: publicAuthClient,
				tokenBinding: COMPOUND_DPOP_BINDING,
			}),
		);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		expect(decodeJwt(result.tokens.access_token).cnf).toEqual({ jkt: "OWNED-JKT" });
		expect(decodeJwt(result.tokens.refresh_token as string).cnf).toEqual({ jkt: "OWNED-JKT" });
		expect(result.tokens.token_type).toBe("DPoP");
	});

	it("stamps the mTLS member of a compound confirmation and nothing else, advertised as Bearer", async () => {
		const rt = await mintRefreshToken({ clientId: PUBLIC_CLIENT_ID });
		const { result } = await createRefreshTokenGrant(mockDeps).handle(
			buildCtx({
				refreshToken: rt,
				authenticatedClient: publicAuthClient,
				tokenBinding: COMPOUND_MTLS_BINDING,
			}),
		);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		expect(decodeJwt(result.tokens.access_token).cnf).toEqual({ "x5t#S256": "OWNED-X5T" });
		expect(decodeJwt(result.tokens.refresh_token as string).cnf).toEqual({
			"x5t#S256": "OWNED-X5T",
		});
		expect(result.tokens.token_type).toBe("Bearer");
	});
});
