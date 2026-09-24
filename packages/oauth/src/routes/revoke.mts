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

import {
	type AccessTokenDenylist,
	type AccessTokenRevocationMode,
	type ClientRepository,
	DEFAULT_CLOCK_SKEW_MS,
	isVerificationUnavailable,
	type JwtVerificationError,
	type KeyStore,
	type Logger,
	loggableError,
	type RefreshTokenFamilyRevocation,
	type ReplaySeenSet,
	verifyJwt,
} from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
import { createClientAuthMiddleware } from "../middleware/clientAuth.mjs";

type ExpressLike = {
	Router: () => Router;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

export interface RevokeRouterOptions {
	readonly clientRepository: ClientRepository;
	readonly keyStore: KeyStore;
	readonly refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation;
	readonly accessTokenDenylist?: AccessTokenDenylist;
	/**
	 * What this endpoint does with an ACCESS token (#277).
	 *
	 * Omitted, it follows what it was handed: `"denylist"` when an
	 * `accessTokenDenylist` is present, `"unsupported"` when it is not. There is
	 * no third behaviour, and in particular no "accept and do nothing".
	 *
	 * Stated as `"denylist"` with no denylist supplied, construction throws —
	 * that is a deployment claiming a capability it cannot perform, and it is
	 * fixable only where the composition is assembled.
	 *
	 * Whether *omitting* the declaration is itself acceptable is decided a layer
	 * up: core's boot validator treats an undeclared
	 * `oauth.revocation.accessToken` as `"denylist"` and refuses a composition
	 * that has no denylist to back it, so a real deployment never reaches this
	 * fallback by accident.
	 */
	readonly accessTokenRevocation?: AccessTokenRevocationMode;
	readonly logger: Logger;
	readonly issuer: string;
	/**
	 * #484: the composition's replay store and the canonical token endpoint,
	 * for `private_key_jwt`. The discovery document advertises the method
	 * for revocation, so the endpoint must verify an assertion the same way
	 * `/oauth/token` does — the same `jti` spent once across both.
	 */
	readonly replaySeenSet?: ReplaySeenSet;
	readonly tokenEndpoint?: string;
}

/**
 * Creates an Express router handling `POST /revoke` per RFC 7009.
 *
 * Behavior summary:
 * - Requires client authentication (both confidential and public clients per RFC 7009 §2.1;
 *   public clients identify via `client_id` form param only — `allowPublicClients: true`).
 * - Accepts `token` + optional `token_type_hint` form params.
 * - Returns 400 `invalid_request` when `token` is absent.
 * - Returns 400 `unsupported_token_type` when `token_type_hint` is present
 *   but not a recognized value — and, under
 *   `accessTokenRevocation: "unsupported"`, for `token_type_hint =
 *   access_token` as well (see the access-token paths below).
 * - Returns 503 `temporarily_unavailable` when the store a revocation writes
 *   to — the access-token denylist or the refresh-token family store —
 *   fails (RFC 7009 §2.2.1), logged at error level as
 *   `revoke_store_unavailable` with the store and the client. The client is
 *   told to assume the token still exists and retry, never that it was
 *   revoked.
 * - Returns the same 503 when the token cannot be verified because the
 *   keystore did not answer (core's `isVerificationUnavailable`), logged at
 *   error level as `token_verification_unavailable` with `site: "revoke"`.
 *   A 200 there would tell the client the token was revoked while nothing
 *   was touched.
 * - Returns 200 for every other outcome (RFC 7009 §2.2 no-info-leak):
 *   the token was revoked, or it did not verify, was not one this server
 *   could use, or belonged to another client. None of those reaches a store.
 *
 * Refresh-token path:
 * - Verifies the RT signature / type / issuer via `verifyJwt` with
 *   `ignoreExpiration: true` (revoking an expired RT is harmless idempotency
 *   per RFC 7009 §2.1).
 * - Extracts `family_id` claim; if absent or verification fails → silent 200.
 * - Verifies client ownership via `azp` (falls back to `aud`).
 * - Calls `refreshTokenFamilyRevocation.revokeFamily(familyId)`; a rejection
 *   is the 503 above.
 * - When `refreshTokenFamilyRevocation` slot is unwired → silent 200.
 *
 * Access-token path (`accessTokenRevocation: "denylist"`):
 * - Verifies AT signature / type / issuer with `ignoreExpiration: true`
 *   (revoking an already-expired AT is also harmless).
 *
 * `ignoreExpiration: true` is allowed at both call sites within this file but
 * NOWHERE else in the codebase — CI lint guardrail T7 enforces this scoping
 * (see `.github/workflows/ci.yml` step `Restrict ignoreExpiration use-site`).
 * - Extracts `jti`, `exp`, `client_id` (or `azp` fallback) from payload.
 * - Verifies client ownership; mismatch → silent 200.
 * - Calls `denylist.add(jti, exp * 1000 + DEFAULT_CLOCK_SKEW_MS)` — denied for
 *   as long as the token can still verify — or, when even that has passed,
 *   asks no store and answers 200: there is nothing left to deny. A
 *   rejection from the store is the 503 above.
 *
 * Access-token path (`accessTokenRevocation: "unsupported"`):
 * - `token_type_hint = access_token` → 400 `unsupported_token_type`
 *   (RFC 7009 §2.2.1). Saying so is the honest answer; a 200 would claim a
 *   revocation that never happened.
 * - Unhinted requests fall back to the refresh-token path only, and still
 *   answer 200 (§2.2 no-info-leak) whether or not the token was an RT.
 *
 * #277: there is no third state. Either a denylist backs the AT path, or the
 * endpoint says the capability is absent — the "verify it, log a warning,
 * answer 200" branch this file used to carry is gone, not relocated.
 */
export function createRevokeRouter(express: ExpressLike, opts: RevokeRouterOptions): Router {
	// Undeclared → follow the wiring. Declared → honour it, and refuse the one
	// combination that cannot be honoured.
	const accessTokenRevocation: AccessTokenRevocationMode =
		opts.accessTokenRevocation ?? (opts.accessTokenDenylist ? "denylist" : "unsupported");
	// What the access-token path writes to: present exactly when the mode is
	// "denylist", which the refusal below guarantees. Resolved here, once, so
	// the path takes it as a value rather than re-reading an optional slot.
	const denylist = accessTokenRevocation === "denylist" ? opts.accessTokenDenylist : undefined;
	if (accessTokenRevocation === "denylist" && !denylist) {
		throw new Error(
			'createRevokeRouter: accessTokenRevocation is "denylist" but no `accessTokenDenylist` was ' +
				"supplied. RFC 7009 requires POST /oauth/revoke to answer 200, so without a denylist an " +
				"operator would be told an access token is revoked while it keeps verifying until it " +
				'expires. Supply a denylist, or pass `accessTokenRevocation: "unsupported"` to have the ' +
				"endpoint reject access-token revocation with unsupported_token_type. Refresh-token " +
				"revocation needs no denylist and works in either mode.",
		);
	}

	const router = express.Router();
	// Scoped to exactly the one path this router serves: it is mounted
	// without a path inside the OAuth router, so an unscoped parser would
	// read the body of every request under `/oauth` that reached it — other
	// modules' too. A route (`router.all`) rather than `router.use`, which
	// would match every path beneath `/revoke` as well.
	router.all("/revoke", express.urlencoded({ extended: false }));

	const clientAuth = createClientAuthMiddleware(opts.clientRepository, {
		issuer: opts.issuer,
		logger: opts.logger,
		...(opts.replaySeenSet === undefined ? {} : { replaySeenSet: opts.replaySeenSet }),
		...(opts.tokenEndpoint === undefined ? {} : { tokenEndpoint: opts.tokenEndpoint }),
		// RFC 7009 §2.1: public clients may revoke their own tokens.
		// Wave 1 dogfood (yoshi SPA + Mobile) uses public-client flows — enabling here
		// is required for the dogfood to work. Ownership check (token's client_id claim
		// vs req.oauthClient.clientId) applies equally to confidential and public clients.
		allowPublicClients: true,
	});

	router.post("/revoke", clientAuth, async (req, res) => {
		const body = (req.body ?? {}) as Record<string, string | undefined>;
		const { token, token_type_hint } = body;

		if (!token) {
			res
				.status(400)
				.json({ error: "invalid_request", error_description: "token form param is required" });
			return;
		}

		if (
			token_type_hint !== undefined &&
			token_type_hint !== "access_token" &&
			token_type_hint !== "refresh_token"
		) {
			res.status(400).json({ error: "unsupported_token_type" });
			return;
		}

		// Defensive: clientAuth sets req.oauthClient before calling next().
		// Absent only if middleware is misconfigured; bail silently to avoid 500.
		const client = req.oauthClient;
		if (!client) {
			res.status(200).end();
			return;
		}

		// RFC 7009 §2.1 cross-type search:
		// - Try the type matching the hint first (or RT-first when no hint is given).
		// - If the first attempt fails to locate/revoke the token, MUST extend the
		//   search to the other type (§2.1: "If the server is unable to locate the
		//   token using the given hint, it MUST extend its search across all of its
		//   supported token types.").
		// "Fails to locate" = an attempt answers `not_located` (wrong type,
		// unverifiable, not this client's). A store that fails is not that: it
		// ends the search as `unavailable`, answered 503 below.
		let outcome: RevocationAttempt;
		if (denylist === undefined) {
			// #277: the capability is declared absent. An explicit AT hint gets the
			// RFC 7009 §2.2.1 answer for exactly this situation rather than a 200
			// that means nothing. An unhinted request is still a legitimate
			// cross-type search — the RT half of it works — so it runs and answers
			// 200 whether or not the token was an RT, per §2.2's no-info-leak rule.
			if (token_type_hint === "access_token") {
				res.status(400).json({ error: "unsupported_token_type" });
				return;
			}
			outcome = await tryRevokeRefreshToken(token, client.clientId, opts);
		} else if (token_type_hint === "access_token") {
			// Hint says AT — try AT first; if it is not one, fall back to RT. This
			// covers the caller that passed hint=access_token with an actual RT.
			outcome = await tryRevokeAccessToken(token, client.clientId, denylist, opts);
			if (outcome === "not_located") {
				outcome = await tryRevokeRefreshToken(token, client.clientId, opts);
			}
		} else {
			// hint=refresh_token or no hint — try RT first, then extend to AT.
			outcome = await tryRevokeRefreshToken(token, client.clientId, opts);
			if (outcome === "not_located") {
				outcome = await tryRevokeAccessToken(token, client.clientId, denylist, opts);
			}
		}

		if (outcome === "unavailable") {
			// RFC 7009 §2.2.1: the client "should assume the token still exists".
			// A 200 here would tell it the opposite while the token keeps
			// verifying until it expires.
			res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "token revocation is temporarily unavailable; retry the request",
			});
			return;
		}

		// RFC 7009 §2.2: 200 whether the token was revoked or not located.
		res.status(200).end();
	});

	return router;
}

/**
 * What one revocation attempt came to.
 *
 * - `revoked` — the token was this client's and its store recorded it.
 * - `not_located` — the token is not one this attempt can revoke: it does
 *   not verify as this type, carries no revocable identity, belongs to
 *   another client, or is past even the default verification tolerance, so
 *   there is nothing left to deny. RFC 7009 §2.2 answers it 200, and the caller extends the
 *   search to the other type.
 * - `unavailable` — the token was this client's, and the store that records
 *   the revocation failed; or the token could not be verified at all because
 *   the keystore did not answer. Already logged, each as its own event; the
 *   caller answers 503.
 */
type RevocationAttempt = "revoked" | "not_located" | "unavailable";

/**
 * A token that could not be verified because the verifier could not consult
 * the keystore (core's `isVerificationUnavailable`): the server's outage, not
 * a finding about the token. Logged; the caller answers 503.
 */
function verificationUnavailable(
	outage: JwtVerificationError,
	opts: RevokeRouterOptions,
): RevocationAttempt {
	opts.logger.error(
		{ site: "revoke", reason: outage.reason, err: loggableError(outage) },
		"token_verification_unavailable",
	);
	return "unavailable";
}

/**
 * Records a revocation in its store, or reports the store's failure. Only a
 * token that verified and belongs to the requesting client reaches here, so
 * the failure is the server's, never a verdict on the token. The log names
 * the store and the client whose revocation was lost — never the token.
 */
async function recordRevocation(
	store: "accessTokenDenylist" | "refreshTokenFamilyRevocation",
	write: () => Promise<void>,
	clientId: string,
	opts: RevokeRouterOptions,
): Promise<RevocationAttempt> {
	try {
		await write();
		return "revoked";
	} catch (err) {
		opts.logger.error({ err: loggableError(err), store, clientId }, "revoke_store_unavailable");
		return "unavailable";
	}
}

/**
 * Attempt to revoke a refresh token by revoking its family.
 *
 * `not_located` sends the caller to the access-token path, or to a silent
 * 200; `unavailable` means the family store failed.
 */
async function tryRevokeRefreshToken(
	token: string,
	requestingClientId: string,
	opts: RevokeRouterOptions,
): Promise<RevocationAttempt> {
	const revocation = opts.refreshTokenFamilyRevocation;
	if (!revocation) {
		return "not_located";
	}
	let familyId: string;
	try {
		const verified = await verifyJwt(token, opts.keyStore, {
			type: "refresh_token",
			expectedIssuer: opts.issuer,
			// Per RFC 7009 §2.1 + spec §4.4: revoke an already-expired RT
			// is harmless idempotency — the family-revocation primitive is
			// idempotent and keeps cascade checks correct. Without this flag,
			// expired-but-valid-signature RTs would throw and bypass revocation.
			// SECURITY GUARDRAIL (§4.5 S9): this is one of two legitimate sites
			// for ignoreExpiration: true (along with the AT path below).
			ignoreExpiration: true,
			// #367: deliberate — the caller is here to revoke; refusing an
			// already-revoked token would break RFC 7009 §2.2's idempotent 200.
			revocation: "none",
		});
		const claims = verified.payload as Record<string, unknown>;

		// Extract family_id — present on tokens minted by v0.5.x+.
		const familyIdRaw = claims.family_id;
		if (typeof familyIdRaw !== "string" || familyIdRaw.length === 0) {
			// No family_id → legacy token; cannot revoke by family.
			return "not_located";
		}
		familyId = familyIdRaw;

		// Verify client ownership: azp takes precedence (D-6 PB-2); fall back to aud.
		const tokenAud = Array.isArray(verified.payload.aud)
			? verified.payload.aud[0]
			: verified.payload.aud;
		const tokenAzp =
			typeof claims.azp === "string" && claims.azp.length > 0 ? claims.azp : tokenAud;
		if (tokenAzp !== requestingClientId) {
			// Wrong owner — silent 200 (RFC 7009 §2.2 no-info-leak).
			return "not_located";
		}
	} catch (err) {
		// A keystore that could not answer → 503. With `revocation: "none"`
		// that is the only outage `verifyJwt` can report here.
		if (isVerificationUnavailable(err)) return verificationUnavailable(err, opts);
		// Invalid signature / wrong type / wrong issuer → silent 200.
		opts.logger?.debug?.(
			{ scope: "oauth.revoke.refresh" },
			"refresh token revoke skipped (verification failed)",
		);
		return "not_located";
	}

	return recordRevocation(
		"refreshTokenFamilyRevocation",
		() => revocation.revokeFamily(familyId),
		requestingClientId,
		opts,
	);
}

/**
 * Attempt to revoke an access token by adding its jti to the denylist.
 *
 * Only reached when `accessTokenRevocation` is `"denylist"`, which
 * `createRevokeRouter` refuses to enter without a denylist (#277) — so the
 * router hands the denylist over as a value, and there is no unwired branch
 * here. The one this function used to carry was the silent no-op the issue
 * was filed about; it is gone rather than moved, because there is no
 * request-time recovery from it.
 *
 * Always resolves (never throws): a token that cannot be revoked is
 * `not_located`, and a denylist that fails, or a keystore that could not
 * answer, is `unavailable`, logged.
 * `ignoreExpiration: true` is intentional and is the ONLY legitimate call site
 * for this option in production code (CI guardrail T7 enforces this).
 */
async function tryRevokeAccessToken(
	token: string,
	requestingClientId: string,
	denylist: AccessTokenDenylist,
	opts: RevokeRouterOptions,
): Promise<RevocationAttempt> {
	let jti: string;
	let exp: number;
	try {
		// ignoreExpiration: true — §4.5 / S9. Revoking an already-expired AT is
		// harmless and semantically correct: the client may not know the AT has
		// expired, and this is the ONLY call site where this option is permitted.
		const verified = await verifyJwt(token, opts.keyStore, {
			type: "access_token",
			expectedIssuer: opts.issuer,
			ignoreExpiration: true,
			// #367: deliberate — same idempotency as the RT path above; a jti
			// already on the denylist gets its RFC 7009 200 without a re-check.
			revocation: "none",
		});
		const claims = verified.payload as Record<string, unknown>;

		const claimedJti = typeof verified.payload.jti === "string" ? verified.payload.jti : undefined;
		const claimedExp = typeof verified.payload.exp === "number" ? verified.payload.exp : undefined;

		if (!claimedJti || !claimedExp) {
			// Malformed AT (no jti or exp) — cannot denylist; silent 200.
			opts.logger.debug({ scope: "oauth.revoke.access" }, "AT revoke skipped: missing jti or exp");
			return "not_located";
		}
		jti = claimedJti;
		exp = claimedExp;

		// Verify client ownership: client_id claim (RFC 9068) or azp fallback.
		const tokenAud = Array.isArray(verified.payload.aud)
			? verified.payload.aud[0]
			: verified.payload.aud;
		const rawClientId = claims.client_id;
		const rawAzp = claims.azp;
		const tokenClientId =
			typeof rawClientId === "string" && rawClientId.length > 0
				? rawClientId
				: typeof rawAzp === "string" && rawAzp.length > 0
					? rawAzp
					: tokenAud;

		// Fail closed: when no owner claim (`client_id` / `azp` / `aud`) is
		// resolvable, we cannot verify ownership → treat as ownership-failure
		// (silent 200 per RFC 7009 §2.2). Matches the symmetric behavior of
		// the RT path (tryRevokeRefreshToken treats undefined azp as mismatch).
		if (tokenClientId === undefined || tokenClientId !== requestingClientId) {
			opts.logger.debug(
				{
					scope: "oauth.revoke.access",
					expected: requestingClientId,
					got: tokenClientId ?? "<missing>",
				},
				"AT revoke skipped: client_id mismatch or missing",
			);
			return "not_located";
		}
	} catch (err) {
		// A keystore that could not answer → 503; see the refresh-token path.
		if (isVerificationUnavailable(err)) return verificationUnavailable(err, opts);
		// Invalid signature / wrong type / wrong issuer → silent 200.
		opts.logger.debug({ scope: "oauth.revoke.access" }, "AT revoke skipped (verification failed)");
		return "not_located";
	}

	// Denied for as long as the token can still verify: `verifyJwt` accepts
	// one up to DEFAULT_CLOCK_SKEW_MS past its `exp` (the default; no verifier in
	// this provider passes another), so an entry that lapsed at `exp` would let a revoked
	// token verify again for that long — the same extension the
	// subject-revocation horizon applies. Once even that has passed there is
	// nothing left to deny, and the store is not asked: a store holding a TTL
	// may refuse an expiry already past, which must not turn RFC 7009 §2.1's
	// legal revocation of an expired token into a 503.
	const deniedUntilMs = exp * 1000 + DEFAULT_CLOCK_SKEW_MS;
	if (deniedUntilMs <= Date.now()) {
		opts.logger.debug({ scope: "oauth.revoke.access" }, "AT revoke skipped: already expired");
		return "not_located";
	}

	return recordRevocation(
		"accessTokenDenylist",
		() => denylist.add(jti, deniedUntilMs),
		requestingClientId,
		opts,
	);
}
