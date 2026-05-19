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
 * Coverage for the DPoP refresh-token binding matrix — Wave 2 Phase 2 §9.2.
 *
 * The 5-row matrix (Codex Round 1 Important #1) governs how the refresh_token
 * grant correlates the RT's persisted `cnf.jkt` claim with the request-time
 * DPoP proof presented via `ctx.tokenBinding`:
 *
 *   | RT cnf.jkt | proof JKT       | Outcome
 *   | no         | no              | row 1: issue plain Bearer (legacy preserved)
 *   | no         | yes             | row 2: opt-in upgrade — bind new AT (RT bound only for public)
 *   | yes        | no              | row 3: reject invalid_grant "requires a DPoP proof"
 *   | yes        | yes, differs    | row 4: reject invalid_grant "does not match refresh_token binding"
 *   | yes        | yes, equal      | row 5: rotation preserves binding (AT + RT for public)
 *
 * Pattern: direct grant handler invocation (mirrors refreshToken.test.mts).
 * RTs are minted via SignJWT with arbitrary cnf claims to drive each row.
 * The matrix check runs BEFORE rotation wiring, so tests use mockDeps without
 * refreshTokenFamilyRotation — orthogonal concerns.
 */

import { createSecretKey } from "node:crypto";
import {
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
	type TokenBinding,
} from "@o3co/auth-provider-core";
import { decodeJwt, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";

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
		accessToken: { expiresIn: 3600 },
		refreshToken: {
			expiresIn: 86400,
			unknownFamilyPolicy: "reject",
			legacyRtPolicy: "reject",
		},
		grants: {
			refresh_token: { enabled: true },
		},
	},
} as unknown as GrantDependencies["config"];

const mockDeps: GrantDependencies = {
	config: mockConfig,
	keyStore,
};

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

describe("DPoP refresh-token binding matrix — §9.2 (5 rows)", () => {
	it("row 1: RT plain + no proof → unbound AT, Bearer", async () => {
		// Pre-DPoP legacy path: the RT was never bound, no proof presented.
		// The grant MUST preserve the existing Bearer-only behavior — this is
		// the regression guard for the opt-in default.
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
		// Public client opt-in upgrade — proof presented for a previously-unbound
		// RT. Per §9.1's public-client gate, the new RT MUST also be bound so a
		// subsequent refresh enforces continuity. Confidential clients in row 2
		// get AT-bound but RT-plain (next sub-test).
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
// Mechanism-boundary regressions (Codex Important #1 + #2 convergence, PR #185)
// ---------------------------------------------------------------------------

describe("DPoP refresh-token mechanism boundary", () => {
	it("non-DPoP mechanism emitting cnf.jkt cannot satisfy a DPoP-bound RT (Codex Important #2)", async () => {
		// The Confirmation union is mechanism-extensible — a custom mechanism
		// (e.g. a future FIDO attestation binding) could emit `{ jkt: "..." }`
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

	it("mTLS public-client refresh leaves new RT plain (Phase 3 mTLS RT-binding deferred — Codex Important #1)", async () => {
		// An mTLS binding on a public client refresh path MUST NOT issue an
		// mTLS-bound RT in Phase 2 — there is no refresh-time mTLS
		// enforcement matrix yet, so a bound RT could later be refreshed
		// without proof and silently degrade to plain. Pins the Phase 2
		// contract; Phase 3 will invert this assertion when mTLS RT-binding
		// + refresh-time enforcement land together.
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
		// mTLS keeps Bearer per RFC 8705 §3
		expect(result.tokens.token_type).toBe("Bearer");
		// AT gets mTLS cnf (mechanism-agnostic propagation per RFC 7800)
		const atPayload = decodeJwt(result.tokens.access_token);
		expect((atPayload.cnf as { "x5t#S256"?: string } | undefined)?.["x5t#S256"]).toBe(
			"MTLS-RT-THUMB",
		);
		// New RT MUST be plain in Phase 2 (the deferred contract).
		expect(result.tokens.refresh_token).toBeTruthy();
		const newRtPayload = decodeJwt(result.tokens.refresh_token as string);
		expect(newRtPayload.cnf).toBeUndefined();
	});
});
