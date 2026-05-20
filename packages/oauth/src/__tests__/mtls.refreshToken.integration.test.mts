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
 * Coverage for the mTLS refresh-token binding matrix — Wave 2 Phase 3 §9.2.
 *
 * Parallel structure to `dpop.refreshToken.integration.test.mts` — the
 * 5-row matrix (mirroring RFC 8705 §4 with a refresh-time enforcement model
 * identical to RFC 9449 §5's DPoP rotation rule) governs how the
 * refresh_token grant correlates the RT's persisted `cnf.x5t#S256` claim
 * with the request-time client certificate presented via `ctx.tokenBinding`:
 *
 *   RT cnf.x5t#S256 | client cert     | Outcome
 *   no              | no              | row 1: issue plain Bearer (legacy)
 *   no              | yes             | row 2: opt-in upgrade — bind new AT (RT bound only for public)
 *   yes             | no              | row 3: reject invalid_grant "requires a client certificate"
 *   yes             | yes, differs    | row 4: reject invalid_grant "does not match refresh_token binding"
 *   yes             | yes, equal      | row 5: rotation preserves binding (AT + RT for public)
 *
 * Plus:
 *   - Compound-cnf rejection (Codex Critical #2): RT carrying BOTH `jkt`
 *     and `x5t#S256` is rejected BEFORE either matrix runs.
 *   - Mechanism-boundary regression: a non-mTLS mechanism emitting an
 *     `{ "x5t#S256": "..." }` confirmation cannot satisfy an mTLS-bound
 *     RT (parallel to PR #185 / Codex Important #2 for DPoP).
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

const CONFIDENTIAL_CLIENT_ID = "mtls-rt-confidential-client";
const PUBLIC_CLIENT_ID = "mtls-rt-public-client";

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
// RT minter — produces signed JWTs with optional cnf claim shapes
// ---------------------------------------------------------------------------

interface MintRtOptions {
	readonly clientId: string;
	readonly cnf?: Record<string, string>;
	readonly sub?: string;
	readonly scope?: string;
}

async function mintRefreshToken(opts: MintRtOptions): Promise<string> {
	const payload: Record<string, unknown> = {
		sub: opts.sub ?? "u1",
		scope: opts.scope ?? "read write",
	};
	if (opts.cnf !== undefined) {
		payload.cnf = opts.cnf;
	}
	return new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setIssuer("localhost")
		.setAudience(opts.clientId)
		.setExpirationTime("24h")
		.sign(secretKey);
}

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

const mtlsBinding = (thumbprint: string): TokenBinding => ({
	kind: "mtls",
	confirmation: { "x5t#S256": thumbprint },
});

// ---------------------------------------------------------------------------
// 5-row matrix tests
// ---------------------------------------------------------------------------

describe("mTLS refresh-token binding matrix — §9.2 (5 rows)", () => {
	it("row 1: RT plain + no cert → unbound AT, Bearer", async () => {
		// Pre-mTLS legacy path: RT was never bound, no cert presented.
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
		expect(decodeJwt(result.tokens.access_token).cnf).toBeUndefined();
		expect(result.tokens.refresh_token).toBeTruthy();
		expect(decodeJwt(result.tokens.refresh_token as string).cnf).toBeUndefined();
	});

	it("row 2 (public client): RT plain + cert → opt-in upgrade, new AT + RT bound", async () => {
		// Public client opt-in upgrade — cert presented for a previously
		// unbound RT. Per §9.1's public-client gate the new RT MUST also
		// carry cnf so a subsequent refresh enforces continuity.
		const rt = await mintRefreshToken({ clientId: PUBLIC_CLIENT_ID });
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: publicAuthClient,
			tokenBinding: mtlsBinding("PUB-THUMB"),
		});

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		// mTLS keeps wire-level Bearer (RFC 8705 §3).
		expect(result.tokens.token_type).toBe("Bearer");
		const atCnf = decodeJwt(result.tokens.access_token).cnf as Record<string, string> | undefined;
		expect(atCnf?.["x5t#S256"]).toBe("PUB-THUMB");
		const newRtCnf = decodeJwt(result.tokens.refresh_token as string).cnf as
			| Record<string, string>
			| undefined;
		expect(newRtCnf?.["x5t#S256"]).toBe("PUB-THUMB");
	});

	it("row 2 (confidential variant): RT plain + cert → AT bound, RT remains plain", async () => {
		// Confidential clients authenticate via client_secret at refresh
		// time (RFC 9449 §5 rationale, generalized to mTLS). RT-binding
		// adds no security and would force cert retention across the RT
		// lifetime.
		const rt = await mintRefreshToken({ clientId: CONFIDENTIAL_CLIENT_ID });
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: confidentialAuthClient,
			tokenBinding: mtlsBinding("CONF-THUMB"),
		});

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		expect(result.tokens.token_type).toBe("Bearer");
		const atCnf = decodeJwt(result.tokens.access_token).cnf as Record<string, string> | undefined;
		expect(atCnf?.["x5t#S256"]).toBe("CONF-THUMB");
		// Confidential client → new RT MUST remain plain.
		expect(decodeJwt(result.tokens.refresh_token as string).cnf).toBeUndefined();
	});

	it("row 3: RT bound + no cert → reject invalid_grant", async () => {
		// The RT itself promised mTLS binding (carries cnf.x5t#S256). A
		// subsequent refresh without a cert would let an attacker who
		// exfiltrated the RT use it freely — the entire point of binding
		// is broken. Hard reject.
		const rt = await mintRefreshToken({
			clientId: PUBLIC_CLIENT_ID,
			cnf: { "x5t#S256": "PROMISED-THUMB" },
		});
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: publicAuthClient,
			// No tokenBinding — cert absent
		});

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(400);
		if (!("error" in result)) expect.fail("Expected error in result");
		expect(result.error).toBe("invalid_grant");
		expect(result.errorDescription).toContain("requires a client certificate");
	});

	it("row 4: RT bound + cert mismatch → reject invalid_grant", async () => {
		// Cert-substitution attack: attacker has stolen the RT but uses
		// their own cert. The thumbprint comparison MUST catch this even
		// though the cert was structurally validated by the mTLS extractor.
		const rt = await mintRefreshToken({
			clientId: PUBLIC_CLIENT_ID,
			cnf: { "x5t#S256": "PROMISED-THUMB" },
		});
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: publicAuthClient,
			tokenBinding: mtlsBinding("ATTACKER-THUMB"),
		});

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(400);
		if (!("error" in result)) expect.fail("Expected error in result");
		expect(result.error).toBe("invalid_grant");
		expect(result.errorDescription).toContain("does not match refresh_token binding");
	});

	it("row 5: RT bound + cert match → rotation preserves binding (public client)", async () => {
		// Happy path for an already-bound public-client RT: the cert's
		// thumbprint equals the persisted cnf.x5t#S256. New AT inherits
		// the binding, new RT also carries it so the next refresh enforces
		// continuity.
		const rt = await mintRefreshToken({
			clientId: PUBLIC_CLIENT_ID,
			cnf: { "x5t#S256": "MATCH-THUMB" },
		});
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: publicAuthClient,
			tokenBinding: mtlsBinding("MATCH-THUMB"),
		});

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("Expected tokens in result");
		expect(result.tokens.token_type).toBe("Bearer");
		const atCnf = decodeJwt(result.tokens.access_token).cnf as Record<string, string> | undefined;
		expect(atCnf?.["x5t#S256"]).toBe("MATCH-THUMB");
		const newRtCnf = decodeJwt(result.tokens.refresh_token as string).cnf as
			| Record<string, string>
			| undefined;
		expect(newRtCnf?.["x5t#S256"]).toBe("MATCH-THUMB");
	});
});

// ---------------------------------------------------------------------------
// Compound-cnf rejection (Codex Critical #2 — Phase 3 §9.2 pre-matrix)
// ---------------------------------------------------------------------------

describe("mTLS refresh-token compound-cnf rejection", () => {
	it("RT carrying BOTH cnf.jkt AND cnf.x5t#S256 → reject before either matrix runs", async () => {
		// Stage 1 supports single-mechanism bindings only. A compound cnf
		// could only arise from a bug or attacker-crafted RT; accepting it
		// would create ambiguous enforcement semantics (which matrix wins?
		// what if jkt matches but x5t doesn't?). The pre-matrix reject
		// closes that ambiguity structurally.
		const rt = await mintRefreshToken({
			clientId: PUBLIC_CLIENT_ID,
			cnf: { jkt: "STALE-JKT", "x5t#S256": "STALE-THUMB" },
		});
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: publicAuthClient,
			tokenBinding: mtlsBinding("STALE-THUMB"),
		});

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(400);
		if (!("error" in result)) expect.fail("Expected error in result");
		expect(result.error).toBe("invalid_grant");
		expect(result.errorDescription).toContain("compound cnf binding");
	});

	it("compound cnf rejected even when no proof presented (defense-in-depth)", async () => {
		// The reject must fire pre-matrix regardless of whether a binding
		// is presented in this request. Even if the attacker omits the
		// proof entirely they should hit the compound-cnf branch (not the
		// DPoP "requires a DPoP proof" branch which could leak which
		// matrix is active).
		const rt = await mintRefreshToken({
			clientId: PUBLIC_CLIENT_ID,
			cnf: { jkt: "X", "x5t#S256": "Y" },
		});
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: publicAuthClient,
		});

		const { result } = await handler.handle(ctx);

		expect(result.status).toBe(400);
		if (!("error" in result)) expect.fail("Expected error in result");
		expect(result.error).toBe("invalid_grant");
		expect(result.errorDescription).toContain("compound cnf binding");
	});
});

// ---------------------------------------------------------------------------
// Mechanism-boundary regression (T3c.7 — parallel to PR #185 DPoP rule)
// ---------------------------------------------------------------------------

describe("mTLS refresh-token mechanism boundary", () => {
	it("non-mTLS mechanism emitting cnf.x5t#S256 cannot satisfy an mTLS-bound RT", async () => {
		// The Confirmation union is mechanism-extensible. A custom binding
		// (e.g. a future FIDO attestation mechanism) could emit
		// `{ "x5t#S256": "..." }` without being mTLS. The matrix's
		// `proofX5t` extraction MUST gate on `kind === "mtls"` so a
		// non-mTLS mechanism cannot satisfy an mTLS-bound RT just by
		// reusing the x5t#S256 confirmation shape.
		const rt = await mintRefreshToken({
			clientId: PUBLIC_CLIENT_ID,
			cnf: { "x5t#S256": "RT-MTLS-BOUND-THUMB" },
		});
		const handler = createRefreshTokenGrant(mockDeps);
		const ctx = buildCtx({
			refreshToken: rt,
			authenticatedClient: publicAuthClient,
			tokenBinding: {
				// Hypothetical non-mTLS mechanism emitting an x5t-shaped cnf.
				// `as TokenBinding` is required because "fido" isn't a known
				// kind value, but the type system allows downstream
				// mechanism authors to extend `kind` via string union.
				kind: "fido",
				confirmation: { "x5t#S256": "RT-MTLS-BOUND-THUMB" },
			} as TokenBinding,
		});

		const { result } = await handler.handle(ctx);

		// MUST reject as row 3 (RT bound, cert absent for mTLS purposes)
		// rather than passing the matrix on x5t structural match. The kind
		// boundary is enforced structurally — not by convention.
		expect(result.status).toBe(400);
		if (!("error" in result)) expect.fail("Expected error in result");
		expect(result.error).toBe("invalid_grant");
		expect(result.errorDescription).toContain("requires a client certificate");
	});
});
