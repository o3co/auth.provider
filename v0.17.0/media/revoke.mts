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
	isVerificationUnavailable,
	type JwtVerificationError,
	type KeyStore,
	type Logger,
	loggableError,
	REVOCATION_RETENTION_ALLOWANCE_MS,
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
	 * What this endpoint does with an access token. Omitted, it follows the
	 * wiring: `"denylist"` when an `accessTokenDenylist` is present, else
	 * `"unsupported"` — never "accept and do nothing". `"denylist"` without a
	 * denylist throws at construction. Core's boot validator treats an
	 * undeclared `oauth.revocation.accessToken` as `"denylist"`, so a deployment
	 * does not reach the fallback by accident.
	 */
	readonly accessTokenRevocation?: AccessTokenRevocationMode;
	readonly logger: Logger;
	readonly issuer: string;
	/**
	 * The replay store and canonical token endpoint for `private_key_jwt`:
	 * discovery advertises the method for revocation, so an assertion is
	 * verified as at `/oauth/token`, with one `jti` spent once across both.
	 */
	readonly replaySeenSet?: ReplaySeenSet;
	readonly tokenEndpoint?: string;
	/** The fetch for a `private_key_jwt` client's `jwksUri`; see `createClientAuthMiddleware`. */
	readonly fetch: typeof fetch;
}

/**
 * Creates an Express router handling `POST /revoke` per RFC 7009.
 *
 * - Requires client authentication; public clients may revoke their own
 *   tokens (§2.1).
 * - `token` is required (400 `invalid_request`); an unknown
 *   `token_type_hint` is 400 `unsupported_token_type`, as is `access_token`
 *   under `accessTokenRevocation: "unsupported"` (§2.2.1: a 200 would claim a
 *   revocation that never happened).
 * - A failing store or an unreachable keystore is 503
 *   `temporarily_unavailable` (§2.2.1): the client must assume the token
 *   still exists, never that it was revoked.
 * - Every other outcome is 200 (§2.2, no information leak): revoked, or not
 *   verifiable, not usable, or another client's — none of which reaches a
 *   store.
 *
 * A refresh token is revoked by its `family_id`; an access token by denying
 * its `jti` for as long as it could still verify. Both paths verify with
 * `ignoreExpiration: true`, since revoking an expired token is harmless
 * (§2.1); CI permits that option only in this file (the `Restrict
 * ignoreExpiration use-site` step).
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
		fetch: opts.fetch,
		// RFC 7009 §2.1: public clients may revoke their own tokens; ownership
		// is checked the same way for every client.
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

		// RFC 7009 §2.1: try the hinted type first (refresh token when unhinted),
		// and when that attempt answers `not_located`, extend the search to the
		// other type. A store failure is not "not located": it ends the search
		// as `unavailable` (503).
		let outcome: RevocationAttempt;
		if (denylist === undefined) {
			// Access-token revocation is declared absent: an explicit hint gets
			// §2.2.1's `unsupported_token_type`; an unhinted request still runs
			// the refresh-token half and answers 200 either way (§2.2).
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
 * What one revocation attempt came to: `revoked`; `not_located` (does not
 * verify as this type, carries no revocable identity, is another client's,
 * or is too old to deny — answered 200, and the search extends to the other
 * type); or `unavailable` (the recording store failed or the keystore did
 * not answer — already logged, answered 503).
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
			// Revoking an expired refresh token is harmless and idempotent (RFC
			// 7009 §2.1); without this, an expired token would escape revocation.
			ignoreExpiration: true,
			// Deliberate: refusing an already-revoked token would break RFC 7009
			// §2.2's idempotent 200.
			revocation: "none",
		});
		const claims = verified.payload as Record<string, unknown>;

		const familyIdRaw = claims.family_id;
		if (typeof familyIdRaw !== "string" || familyIdRaw.length === 0) {
			// No family_id → legacy token; cannot revoke by family.
			return "not_located";
		}
		familyId = familyIdRaw;

		// Client ownership: `azp`, falling back to `aud`.
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
 * Attempt to revoke an access token by adding its jti to the denylist. Only
 * reached in `"denylist"` mode, where the router guarantees a denylist.
 * Never throws: an unrevocable token is `not_located`; a failing denylist or
 * an unreachable keystore is `unavailable`, logged.
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
		// Revoking an expired access token is harmless: the client may not know
		// it has expired.
		const verified = await verifyJwt(token, opts.keyStore, {
			type: "access_token",
			expectedIssuer: opts.issuer,
			ignoreExpiration: true,
			// Deliberate, as on the refresh-token path: a jti already denied gets
			// its RFC 7009 200 without a re-check.
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

	// Denied for as long as the token can still verify: `verifyJwt` accepts a
	// token up to its clock tolerance past `exp`, and core's
	// REVOCATION_RETENTION_ALLOWANCE_MS is that tolerance plus the replica
	// allowance and a rounding second. Once even that has passed there is
	// nothing to deny and no store is asked: a TTL store may refuse a past
	// expiry, which must not turn a legal revocation (RFC 7009 §2.1) into a 503.
	const deniedUntilMs = exp * 1000 + REVOCATION_RETENTION_ALLOWANCE_MS;
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
