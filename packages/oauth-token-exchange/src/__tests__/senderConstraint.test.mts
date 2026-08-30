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
 * Issue #265 — sender-constraint handling in the RFC 8693 exchange grant.
 *
 * The grant did no `cnf` handling at all: a DPoP- or mTLS-bound
 * `subject_token` was accepted with no proof-of-possession and the issued
 * token dropped the binding, so exchange laundered a stolen bound token into
 * a usable bearer token. These tests pin the same 5-row matrix per mechanism
 * that `packages/oauth/src/grants/refreshToken.mts` established for refresh.
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
import { createTokenExchangeGrant } from "#/grant.mjs";
import { ExchangeTokenValidatorRegistry } from "#/validator/registry.mjs";
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
	allowedRedirectUris: [],
	allowedScopes: [],
	allowedAudiences: [],
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
	const registry = new ExchangeTokenValidatorRegistry();
	registry.register(
		ACCESS_TOKEN_TYPE,
		createSelfIssuedAccessTokenValidator({
			keyStore,
			issuer: ISSUER,
			refreshTokenFamilyRevocation: store,
		}),
	);
	return createTokenExchangeGrant({
		keyStore,
		config: mockConfig,
		clientRepository,
		refreshTokenFamilyRevocation: store,
		tokenExchangeValidatorResolver: registry,
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

describe("token exchange — DPoP binding matrix (#265)", () => {
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

	it("bound subject, no proof → invalid_grant (the de-binding laundry)", async () => {
		// The #265 attack: a stolen bound subject_token exchanged by a client
		// that cannot prove possession of the binding key.
		const res = await exchange({ cnf: { jkt: JKT } });
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_grant");
	});

	it("bound subject, proof from a different key → invalid_grant", async () => {
		const res = await exchange({ cnf: { jkt: JKT } }, otherDpopBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_grant");
	});

	it("bound subject, matching proof → issues a token preserving the binding", async () => {
		const res = await exchange({ cnf: { jkt: JKT } }, dpopBinding);
		expect(res.status).toBe(200);
		expect(res.cnf).toEqual({ jkt: JKT });
	});

	it("does not let an mTLS binding satisfy a jkt-bound subject", async () => {
		const res = await exchange({ cnf: { jkt: JKT } }, mtlsBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_grant");
	});
});

// ---------------------------------------------------------------------------
// mTLS matrix (RFC 8705) — parallel to DPoP
// ---------------------------------------------------------------------------

describe("token exchange — mTLS binding matrix (#265)", () => {
	it("unbound subject, certificate presented → binds the issued token", async () => {
		const res = await exchange({}, mtlsBinding);
		expect(res.status).toBe(200);
		expect(res.cnf).toEqual({ "x5t#S256": X5T });
	});

	it("bound subject, no certificate → invalid_grant", async () => {
		const res = await exchange({ cnf: { "x5t#S256": X5T } });
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_grant");
	});

	it("bound subject, different certificate → invalid_grant", async () => {
		const res = await exchange({ cnf: { "x5t#S256": X5T } }, otherMtlsBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_grant");
	});

	it("bound subject, matching certificate → issues a token preserving the binding", async () => {
		const res = await exchange({ cnf: { "x5t#S256": X5T } }, mtlsBinding);
		expect(res.status).toBe(200);
		expect(res.cnf).toEqual({ "x5t#S256": X5T });
	});

	it("does not let a DPoP binding satisfy an x5t#S256-bound subject", async () => {
		const res = await exchange({ cnf: { "x5t#S256": X5T } }, dpopBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_grant");
	});
});

// ---------------------------------------------------------------------------
// Mechanism identity and malformed cnf
// ---------------------------------------------------------------------------

describe("token exchange — cnf edge cases (#265)", () => {
	it("rejects a subject token carrying a compound cnf", async () => {
		// This AS never mints one, so a compound cnf means a forged token.
		const res = await exchange({ cnf: { jkt: JKT, "x5t#S256": X5T } }, dpopBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_grant");
	});

	it("does not let a third-party mechanism kind satisfy a jkt binding", async () => {
		// `Confirmation` is a mechanism-extensible union, so a mechanism that
		// never validated a DPoP proof could still emit `{ jkt }`.
		const impostor: TokenBinding = { kind: "impostor", confirmation: { jkt: JKT } };
		const res = await exchange({ cnf: { jkt: JKT } }, impostor);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_grant");
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
// Actor matrix (#309) — the residual #265 deliberately left open
// ---------------------------------------------------------------------------

/**
 * `exchange` with an `actor_token` alongside the subject.
 *
 * The subject defaults to unbound so each matrix row is driven by the actor's
 * `cnf` alone — a bound subject would consume the single `ctx.tokenBinding`
 * and confound which of the two tokens caused the rejection. `subjectClaims`
 * overrides that for the one row that deliberately binds both, which is the
 * only delegation shape a single binding can carry.
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
 * #265 enforced the subject's `cnf` and named the actor as a tracked residual:
 * a request carries exactly one `ctx.tokenBinding`, so "enforce both" is not a
 * rule any caller could satisfy when the two tokens are bound to different
 * keys. The consequence was that a sender-constrained `actor_token` was
 * accepted with no proof-of-possession at all, while `buildActClaim` folded
 * its identity into the issued token's `act` claim (RFC 8693 §4.1) — a stolen
 * bound actor token forged the delegation chain recorded on the issued token.
 *
 * The rule below is the subject matrix applied to the actor, and it is the
 * strictest one that is physically expressible: match the presented binding or
 * be refused. `AuthenticatedClient` carries no certificate thumbprint of its
 * own — for an mTLS-authenticated client the certificate IS `ctx.tokenBinding`
 * — so there is no second credential to check an actor's `cnf` against.
 *
 * What this deliberately does not support: delegation where the actor and the
 * subject are bound to *different* keys. That needs more than one proof per
 * request, which RFC 9449 has no token-endpoint precedent for; it stays out of
 * scope rather than being approximated by a rule that enforces nothing.
 */
describe("token exchange — actor_token DPoP binding matrix (#309)", () => {
	it("unbound actor, no proof → exchanges and records the delegation", async () => {
		const res = await exchangeWithActor({});
		expect(res.status).toBe(200);
		expect(res.act).toMatchObject({ sub: "actor-1" });
	});

	it("unbound actor, proof presented → exchanges", async () => {
		const res = await exchangeWithActor({}, dpopBinding);
		expect(res.status).toBe(200);
	});

	// The #309 finding itself.
	it("bound actor, no proof → invalid_grant", async () => {
		const res = await exchangeWithActor({ cnf: { jkt: JKT } });
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_grant");
		expect(res.errorDescription).toContain("actor_token");
	});

	it("bound actor, proof from a different key → invalid_grant", async () => {
		const res = await exchangeWithActor({ cnf: { jkt: JKT } }, otherDpopBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_grant");
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
		expect(res.error).toBe("invalid_grant");
	});
});

describe("token exchange — actor_token mTLS binding matrix (#309)", () => {
	it("bound actor, no certificate → invalid_grant", async () => {
		const res = await exchangeWithActor({ cnf: { "x5t#S256": X5T } });
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_grant");
		expect(res.errorDescription).toContain("actor_token");
	});

	it("bound actor, different certificate → invalid_grant", async () => {
		const res = await exchangeWithActor({ cnf: { "x5t#S256": X5T } }, otherMtlsBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_grant");
	});

	it("bound actor, matching certificate → exchanges", async () => {
		const res = await exchangeWithActor({ cnf: { "x5t#S256": X5T } }, mtlsBinding);
		expect(res.status).toBe(200);
		expect(res.act).toMatchObject({ sub: "actor-1" });
	});

	it("does not let a DPoP binding satisfy an x5t#S256-bound actor", async () => {
		const res = await exchangeWithActor({ cnf: { "x5t#S256": X5T } }, dpopBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_grant");
	});
});

describe("token exchange — actor_token cnf edge cases (#309)", () => {
	it("rejects an actor token carrying a compound cnf", async () => {
		const res = await exchangeWithActor({ cnf: { jkt: JKT, "x5t#S256": X5T } }, dpopBinding);
		expect(res.status).toBe(400);
		expect(res.error).toBe("invalid_grant");
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
