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
	type KeyStore,
	type Logger,
	type RefreshTokenFamilyRevocation,
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
 * - Returns 200 for every other outcome (RFC 7009 §2.2 no-info-leak),
 *   whether or not the token existed or belonged to the caller.
 *
 * Refresh-token path:
 * - Verifies the RT signature / type / issuer via `verifyJwt` with
 *   `ignoreExpiration: true` (revoking an expired RT is harmless idempotency
 *   per RFC 7009 §2.1).
 * - Extracts `family_id` claim; if absent or verification fails → silent 200.
 * - Verifies client ownership via `azp` (falls back to `aud`).
 * - Calls `refreshTokenFamilyRevocation.revokeFamily(familyId)`.
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
 * - Calls `denylist.add(jti, exp * 1000)`.
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
	if (accessTokenRevocation === "denylist" && !opts.accessTokenDenylist) {
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
	router.use(express.urlencoded({ extended: false }));

	const clientAuth = createClientAuthMiddleware(opts.clientRepository, {
		issuer: opts.issuer,
		logger: opts.logger,
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
		// "Fails to locate" = tryRevoke* returns false (wrong type / unverifiable).
		// RFC 7009 §2.2: always 200 regardless of outcome.
		if (accessTokenRevocation === "unsupported") {
			// #277: the capability is declared absent. An explicit AT hint gets the
			// RFC 7009 §2.2.1 answer for exactly this situation rather than a 200
			// that means nothing. An unhinted request is still a legitimate
			// cross-type search — the RT half of it works — so it runs and answers
			// 200 either way, per §2.2's no-info-leak rule.
			if (token_type_hint === "access_token") {
				res.status(400).json({ error: "unsupported_token_type" });
				return;
			}
			await tryRevokeRefreshToken(token, client.clientId, opts);
			res.status(200).end();
			return;
		}

		if (token_type_hint === "access_token") {
			// Hint says AT — try AT first; if not found, fall back to RT.
			await tryRevokeAccessToken(token, client.clientId, opts);
			// AT path always resolves (never returns a "found" bool); unconditional
			// cross-type fallback would double-revoke on success. Per spec the AT
			// path is self-contained — if `jti` was added to the denylist that IS
			// the revocation. But if the token didn't parse as an AT, we should try RT.
			// tryRevokeAccessToken swallows all errors, so we always fall through here;
			// attempting RT is harmless (silent 200 on mismatch). This covers the case
			// where the caller passed hint=access_token with an actual RT.
			await tryRevokeRefreshToken(token, client.clientId, opts);
		} else {
			// hint=refresh_token or no hint — try RT first.
			const revoked = await tryRevokeRefreshToken(token, client.clientId, opts);
			if (!revoked) {
				// RT path failed to locate/revoke — extend search to AT per §2.1.
				await tryRevokeAccessToken(token, client.clientId, opts);
			}
		}

		// RFC 7009 §2.2: always 200 regardless of whether the token existed.
		res.status(200).end();
	});

	return router;
}

/**
 * Attempt to revoke a refresh token.
 *
 * Returns `true` if revocation was performed (the RT was valid and belonged to
 * the requesting client). Returns `false` for any other outcome — caller
 * should then try the access-token path or return 200 silently.
 */
async function tryRevokeRefreshToken(
	token: string,
	requestingClientId: string,
	opts: RevokeRouterOptions,
): Promise<boolean> {
	if (!opts.refreshTokenFamilyRevocation) {
		return false;
	}
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
		});
		const claims = verified.payload as Record<string, unknown>;

		// Extract family_id — present on tokens minted by v0.5.x+.
		const familyIdRaw = claims.family_id;
		const familyId = typeof familyIdRaw === "string" && familyIdRaw.length > 0 ? familyIdRaw : null;
		if (!familyId) {
			// No family_id → legacy token; cannot revoke by family.
			return false;
		}

		// Verify client ownership: azp takes precedence (D-6 PB-2); fall back to aud.
		const tokenAud = Array.isArray(verified.payload.aud)
			? verified.payload.aud[0]
			: verified.payload.aud;
		const tokenAzp =
			typeof claims.azp === "string" && claims.azp.length > 0 ? claims.azp : tokenAud;
		if (tokenAzp !== requestingClientId) {
			// Wrong owner — silent 200 (RFC 7009 §2.2 no-info-leak).
			return false;
		}

		await opts.refreshTokenFamilyRevocation.revokeFamily(familyId);
		return true;
	} catch {
		// Invalid signature / wrong type / wrong issuer → silent 200.
		opts.logger?.debug?.(
			{ scope: "oauth.revoke.refresh" },
			"refresh token revoke skipped (verification failed)",
		);
		return false;
	}
}

/**
 * Attempt to revoke an access token by adding its jti to the denylist.
 *
 * Only reached when `accessTokenRevocation` is `"denylist"`, which
 * `createRevokeRouter` refuses to enter without a denylist (#277) — hence
 * `denylist` below is a guaranteed value, not an optional one. The unwired
 * branch this function used to carry was the silent no-op the issue was filed
 * about; it is gone rather than moved, because there is no request-time
 * recovery from it.
 *
 * Always resolves (never throws) — failures are logged and swallowed.
 * `ignoreExpiration: true` is intentional and is the ONLY legitimate call site
 * for this option in production code (CI guardrail T7 enforces this).
 */
async function tryRevokeAccessToken(
	token: string,
	requestingClientId: string,
	opts: RevokeRouterOptions,
): Promise<void> {
	const denylist = opts.accessTokenDenylist;
	if (!denylist) {
		// Unreachable via createRevokeRouter, which refuses this composition at
		// construction. Kept as a typed narrowing, not as a fallback behaviour.
		return;
	}
	try {
		// ignoreExpiration: true — §4.5 / S9. Revoking an already-expired AT is
		// harmless and semantically correct: the client may not know the AT has
		// expired, and this is the ONLY call site where this option is permitted.
		const verified = await verifyJwt(token, opts.keyStore, {
			type: "access_token",
			expectedIssuer: opts.issuer,
			ignoreExpiration: true,
		});
		const claims = verified.payload as Record<string, unknown>;

		const jti = typeof verified.payload.jti === "string" ? verified.payload.jti : undefined;
		const exp = typeof verified.payload.exp === "number" ? verified.payload.exp : undefined;

		if (!jti || !exp) {
			// Malformed AT (no jti or exp) — cannot denylist; silent 200.
			opts.logger.debug({ scope: "oauth.revoke.access" }, "AT revoke skipped: missing jti or exp");
			return;
		}

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
			return;
		}

		await denylist.add(jti, exp * 1000);
	} catch {
		// Invalid signature / wrong type / wrong issuer → silent 200.
		opts.logger.debug({ scope: "oauth.revoke.access" }, "AT revoke skipped (verification failed)");
	}
}
