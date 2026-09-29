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
 * Sender-constraint handling in the RFC 8693 exchange grant. A DPoP- or
 * mTLS-bound `subject_token` needs proof of possession and the issued token
 * keeps the binding, or exchange would launder a stolen bound token into a
 * usable bearer token. The same 5-row matrix per mechanism as
 * `packages/oauth/src/grants/refreshToken.mts`, except the refusal code:
 * refresh answers RFC 6749's `invalid_grant` for its refresh token, the
 * exchange RFC 8693 §2.2.2's `invalid_request` for an unacceptable
 * subject_token or actor_token.
 */

import type {
	AppConfig,
	ClientRepository,
	GrantContext,
	PublicClient,
	TokenBinding,
} from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { createTokenExchangeGrant, TOKEN_EXCHANGE_GRANT_TYPE } from "#/grant.mjs";
import { createSelfIssuedAccessTokenValidator } from "#/validator/selfIssuedAccessToken.mjs";
import { ISSUER, keyStore, makeFamilyRevocation, signSelfIssuedAccessToken } from "./fixtures.mjs";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

const JKT = "L0AXB6c64d2QW3rhCLLADhOMLf_7u2eTGH-q9ZGja24";
const OTHER_JKT = "ZmFrZS1qa3QtdGhhdC1pcy1ub3QtdGhlLXNhbWUtdmFsdWU";
const X5T = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2";
const OTHER_X5T = "ZmFrZS10aHVtYnByaW50LXRoYXQtaXMtbm90LXRoZS1zYW1l";

const mockConfig = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 300 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
} as unknown as AppConfig;

const publicClient = (): PublicClient => ({
	clientId: "client-a",
	tokenEndpointAuthMethod: "none",
	allowedRedirectUris: [],
	// `signSelfIssuedAccessToken` defaults the subject to `scope: "read"`; the
	// client's `allowedScopes` caps the granted scope, and the exchange grant
	// denies by absence of `allowedGrantTypes`. Neither gate is tested here;
	// both must be satisfied to reach the binding matrix.
	allowedScopes: ["read"],
	allowedAudiences: [],
	allowedGrantTypes: [TOKEN_EXCHANGE_GRANT_TYPE],
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutSessionRequired: true,
	allowedAzpForFederationToken: false,
});

const clientRepository: ClientRepository = {
	findById: async (id) => (id === "client-a" ? publicClient() : null),
	authenticate: async (id) => (id === "client-a" ? publicClient() : null),
};

const buildGrant = () => {
	const store = makeFamilyRevocation();
	// The resolver the grant reads is `get` alone, which a Map provides.
	const validators = new Map([
		[ACCESS_TOKEN_TYPE, createSelfIssuedAccessTokenValidator({ keyStore, issuer: ISSUER })],
	]);
	return createTokenExchangeGrant({
		keyStore,
		config: mockConfig,
		clientRepository,
		refreshTokenFamilyRevocation: store,
		tokenExchangeValidatorResolver: validators,
	} as never);
};

const dpopBinding: TokenBinding = { kind: "dpop", confirmation: { jkt: JKT } };
const otherDpopBinding: TokenBinding = { kind: "dpop", confirmation: { jkt: OTHER_JKT } };
const mtlsBinding: TokenBinding = { kind: "mtls", confirmation: { "x5t#S256": X5T } };
const otherMtlsBinding: TokenBinding = {
	kind: "mtls",
	confirmation: { "x5t#S256": OTHER_X5T },
};

const exchange = async (
	subjectClaims: Record<string, unknown>,
	tokenBinding?: TokenBinding,
): Promise<{ status: number; error?: string; cnf?: unknown }> => {
	const subjectToken = await signSelfIssuedAccessToken(subjectClaims);
	const context: GrantContext = {
		body: {
			client_id: "client-a",
			client_secret: "s",
			subject_token: subjectToken,
			subject_token_type: ACCESS_TOKEN_TYPE,
		},
		session: {},
		issuer: ISSUER,
		metadata: {},
		authenticatedClient: null,
		...(tokenBinding ? { tokenBinding } : {}),
	};
	const { result } = await buildGrant().handle(context);
	if ("tokens" in result) {
		const claims = decodeJwt(result.tokens.access_token as string);
		return { status: result.status, cnf: (claims as { cnf?: unknown }).cnf };
	}
	return { status: result.status, error: result.error };
};

// ---------------------------------------------------------------------------
// DPoP matrix (RFC 9449) — mirrors refreshToken.mts
// ---------------------------------------------------------------------------

describe("token exchange — DPoP binding matrix", () => {
	it("unbound subject, no proof → issues a plain Bearer token", async () => {
		const res = await exchange({});
		expect(res.status).toBe(200);
		expect(res.cnf).toBeUndefined();
	});

	it("unbound subject, proof presented → binds the issued token (opt-in upgrade)", async () => {
		const res = await exchange({}, dpopBinding);
		expect(res.status).toBe(200);
		expect(res.cnf).toEqual({ jkt: JKT });
	});

	it("bound subject, no proof → invalid_request (the de-binding laundry)", async () => {
		// The attack: a stolen bound subject_token exchanged by a client that
		// cannot prove possession of the binding key.
		const res = await exchange({ cnf: { jkt: JKT } });
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
	});

	it("bound subject, proof from a different key → invalid_request", async () => {
		const res = await exchange({ cnf: { jkt: JKT } }, otherDpopBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
	});

	it("bound subject, matching proof → issues a token preserving the binding", async () => {
		const res = await exchange({ cnf: { jkt: JKT } }, dpopBinding);
		expect(res.status).toBe(200);
		expect(res.cnf).toEqual({ jkt: JKT });
	});

	it("does not let an mTLS binding satisfy a jkt-bound subject", async () => {
		const res = await exchange({ cnf: { jkt: JKT } }, mtlsBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
	});
});

// ---------------------------------------------------------------------------
// mTLS matrix (RFC 8705) — parallel to DPoP
// ---------------------------------------------------------------------------

describe("token exchange — mTLS binding matrix", () => {
	it("unbound subject, certificate presented → binds the issued token", async () => {
		const res = await exchange({}, mtlsBinding);
		expect(res.status).toBe(200);
		expect(res.cnf).toEqual({ "x5t#S256": X5T });
	});

	it("bound subject, no certificate → invalid_request", async () => {
		const res = await exchange({ cnf: { "x5t#S256": X5T } });
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
	});

	it("bound subject, different certificate → invalid_request", async () => {
		const res = await exchange({ cnf: { "x5t#S256": X5T } }, otherMtlsBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
	});

	it("bound subject, matching certificate → issues a token preserving the binding", async () => {
		const res = await exchange({ cnf: { "x5t#S256": X5T } }, mtlsBinding);
		expect(res.status).toBe(200);
		expect(res.cnf).toEqual({ "x5t#S256": X5T });
	});

	it("does not let a DPoP binding satisfy an x5t#S256-bound subject", async () => {
		const res = await exchange({ cnf: { "x5t#S256": X5T } }, dpopBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
	});
});

// ---------------------------------------------------------------------------
// Mechanism identity and malformed cnf
// ---------------------------------------------------------------------------

describe("token exchange — cnf edge cases", () => {
	it("rejects a subject token carrying a compound cnf", async () => {
		// This AS never mints one, so a compound cnf means a forged token.
		const res = await exchange({ cnf: { jkt: JKT, "x5t#S256": X5T } }, dpopBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
	});

	it("does not let a third-party mechanism kind satisfy a jkt binding", async () => {
		// `Confirmation` is a mechanism-extensible union, so a mechanism that
		// never validated a DPoP proof could still emit `{ jkt }`.
		const impostor: TokenBinding = { kind: "impostor", confirmation: { jkt: JKT } };
		const res = await exchange({ cnf: { jkt: JKT } }, impostor);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
	});

	it("treats a cnf that names no known binding as unbound", async () => {
		const res = await exchange({ cnf: { unknown_member: "x" } });
		expect(res.status).toBe(200);
		expect(res.cnf).toBeUndefined();
	});

	it("treats a non-object cnf as unbound rather than crashing", async () => {
		const res = await exchange({ cnf: "not-an-object" });
		expect(res.status).toBe(200);
		expect(res.cnf).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// Actor matrix
// ---------------------------------------------------------------------------

/**
 * `exchange` with an `actor_token` alongside the subject. The subject defaults
 * to unbound so each row is driven by the actor's `cnf` alone (a bound subject
 * would consume the single `ctx.tokenBinding` and confound which token caused
 * the rejection); `subjectClaims` overrides that for the one row that binds
 * both, the only delegation shape a single binding can carry.
 */
const exchangeWithActor = async (
	actorClaims: Record<string, unknown>,
	tokenBinding?: TokenBinding,
	subjectClaims: Record<string, unknown> = {},
): Promise<{ status: number; error?: string; errorDescription?: string; act?: unknown }> => {
	const subjectToken = await signSelfIssuedAccessToken(subjectClaims);
	const actorToken = await signSelfIssuedAccessToken({ sub: "actor-1", ...actorClaims });
	const context: GrantContext = {
		body: {
			client_id: "client-a",
			client_secret: "s",
			subject_token: subjectToken,
			subject_token_type: ACCESS_TOKEN_TYPE,
			actor_token: actorToken,
			actor_token_type: ACCESS_TOKEN_TYPE,
		},
		session: {},
		issuer: ISSUER,
		metadata: {},
		authenticatedClient: null,
		...(tokenBinding ? { tokenBinding } : {}),
	};
	const { result } = await buildGrant().handle(context);
	if ("tokens" in result) {
		const claims = decodeJwt(result.tokens.access_token as string);
		return { status: result.status, act: (claims as { act?: unknown }).act };
	}
	return {
		status: result.status,
		error: result.error,
		errorDescription: result.errorDescription,
	};
};

/*
 * A sender-constrained `actor_token` needs proof of possession too:
 * `buildActClaim` folds its identity into the issued token's `act` claim
 * (RFC 8693 §4.1), so a stolen bound actor token would forge the delegation
 * chain recorded on the issued token.
 *
 * The rule is the subject matrix applied to the actor, the strictest one that
 * is physically expressible: match the presented binding or be refused. A
 * request carries exactly one `ctx.tokenBinding`, and `AuthenticatedClient`
 * carries no certificate thumbprint of its own (for an mTLS-authenticated
 * client the certificate IS `ctx.tokenBinding`), so there is no second
 * credential to check an actor's `cnf` against.
 *
 * Not supported: an actor and a subject bound to *different* keys. That needs
 * more than one proof per request, which RFC 9449 has no token-endpoint
 * precedent for; it stays out of scope rather than approximated by a rule
 * that enforces nothing.
 */
describe("token exchange — actor_token DPoP binding matrix", () => {
	it("unbound actor, no proof → exchanges and records the delegation", async () => {
		const res = await exchangeWithActor({});
		expect(res.status).toBe(200);
		expect(res.act).toMatchObject({ sub: "actor-1" });
	});

	it("unbound actor, proof presented → exchanges", async () => {
		const res = await exchangeWithActor({}, dpopBinding);
		expect(res.status).toBe(200);
	});

	// The core case: a stolen bound actor token, no proof.
	it("bound actor, no proof → invalid_request", async () => {
		const res = await exchangeWithActor({ cnf: { jkt: JKT } });
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
		expect(res.errorDescription).toContain("actor_token");
	});

	it("bound actor, proof from a different key → invalid_request", async () => {
		const res = await exchangeWithActor({ cnf: { jkt: JKT } }, otherDpopBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
		expect(res.errorDescription).toContain("actor_token");
	});

	it("bound actor, matching proof → exchanges and records the delegation", async () => {
		const res = await exchangeWithActor({ cnf: { jkt: JKT } }, dpopBinding);
		expect(res.status).toBe(200);
		expect(res.act).toMatchObject({ sub: "actor-1" });
	});

	it("does not let an mTLS binding satisfy a jkt-bound actor", async () => {
		const res = await exchangeWithActor({ cnf: { jkt: JKT } }, mtlsBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
	});
});

describe("token exchange — actor_token mTLS binding matrix", () => {
	it("bound actor, no certificate → invalid_request", async () => {
		const res = await exchangeWithActor({ cnf: { "x5t#S256": X5T } });
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
		expect(res.errorDescription).toContain("actor_token");
	});

	it("bound actor, different certificate → invalid_request", async () => {
		const res = await exchangeWithActor({ cnf: { "x5t#S256": X5T } }, otherMtlsBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
	});

	it("bound actor, matching certificate → exchanges", async () => {
		const res = await exchangeWithActor({ cnf: { "x5t#S256": X5T } }, mtlsBinding);
		expect(res.status).toBe(200);
		expect(res.act).toMatchObject({ sub: "actor-1" });
	});

	it("does not let a DPoP binding satisfy an x5t#S256-bound actor", async () => {
		const res = await exchangeWithActor({ cnf: { "x5t#S256": X5T } }, dpopBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
	});
});

describe("token exchange — actor_token cnf edge cases", () => {
	it("rejects an actor token carrying a compound cnf", async () => {
		const res = await exchangeWithActor({ cnf: { jkt: JKT, "x5t#S256": X5T } }, dpopBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_request");
		expect(res.errorDescription).toContain("actor_token");
	});

	it("treats an actor cnf that names no known binding as unbound", async () => {
		const res = await exchangeWithActor({ cnf: { unknown_member: "x" } });
		expect(res.status).toBe(200);
	});

	it("treats a non-object actor cnf as unbound rather than crashing", async () => {
		const res = await exchangeWithActor({ cnf: "not-an-object" });
		expect(res.status).toBe(200);
	});

	// Both bound to the same key is the one delegation shape a single
	// `ctx.tokenBinding` can carry, and it must keep working.
	it("accepts a bound subject and a bound actor when both name the presented key", async () => {
		const res = await exchangeWithActor({ cnf: { jkt: JKT } }, dpopBinding, {
			cnf: { jkt: JKT },
		});
		expect(res.status).toBe(200);
		expect(res.act).toMatchObject({ sub: "actor-1" });
	});
});
