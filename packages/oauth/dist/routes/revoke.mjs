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
import { verifyJwt, } from "@o3co/auth-provider-core";
import { createClientAuthMiddleware } from "../middleware/clientAuth.mjs";
/**
 * Creates an Express router handling `POST /revoke` per RFC 7009.
 *
 * Behavior summary:
 * - Requires client authentication (both confidential and public clients per RFC 7009 §2.1;
 *   public clients identify via `client_id` form param only — `allowPublicClients: true`).
 * - Accepts `token` + optional `token_type_hint` form params.
 * - Returns 400 `invalid_request` when `token` is absent.
 * - Returns 400 `unsupported_token_type` when `token_type_hint` is present
 *   but not a recognized value.
 * - ALWAYS returns 200 for all other outcomes (RFC 7009 §2.2 no-info-leak).
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
 * Access-token path:
 * - Verifies AT signature / type / issuer with `ignoreExpiration: true`
 *   (revoking an already-expired AT is also harmless).
 *
 * `ignoreExpiration: true` is allowed at both call sites within this file but
 * NOWHERE else in the codebase — CI lint guardrail T7 enforces this scoping
 * (see `.github/workflows/ci.yml` step `Restrict ignoreExpiration use-site`).
 * - Extracts `jti`, `exp`, `client_id` (or `azp` fallback) from payload.
 * - Verifies client ownership; mismatch → silent 200.
 * - When `accessTokenDenylist` slot is wired: calls `denylist.add(jti, exp * 1000)`.
 * - When `accessTokenDenylist` slot is unwired: logs warn + silent 200.
 */
export function createRevokeRouter(express, opts) {
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
        const body = (req.body ?? {});
        const { token, token_type_hint } = body;
        if (!token) {
            res
                .status(400)
                .json({ error: "invalid_request", error_description: "token form param is required" });
            return;
        }
        if (token_type_hint !== undefined &&
            token_type_hint !== "access_token" &&
            token_type_hint !== "refresh_token") {
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
        }
        else {
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
async function tryRevokeRefreshToken(token, requestingClientId, opts) {
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
        const claims = verified.payload;
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
        const tokenAzp = typeof claims.azp === "string" && claims.azp.length > 0 ? claims.azp : tokenAud;
        if (tokenAzp !== requestingClientId) {
            // Wrong owner — silent 200 (RFC 7009 §2.2 no-info-leak).
            return false;
        }
        await opts.refreshTokenFamilyRevocation.revokeFamily(familyId);
        return true;
    }
    catch {
        // Invalid signature / wrong type / wrong issuer → silent 200.
        opts.logger?.debug?.({ scope: "oauth.revoke.refresh" }, "refresh token revoke skipped (verification failed)");
        return false;
    }
}
/**
 * Attempt to revoke an access token by adding its jti to the denylist.
 *
 * Always resolves (never throws) — failures are logged and swallowed.
 * `ignoreExpiration: true` is intentional and is the ONLY legitimate call site
 * for this option in production code (CI guardrail T7 enforces this).
 */
async function tryRevokeAccessToken(token, requestingClientId, opts) {
    if (!opts.accessTokenDenylist) {
        opts.logger.warn({ scope: "oauth.revoke.access" }, "AT revocation requested but accessTokenDenylist slot is unwired; no-op");
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
        const claims = verified.payload;
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
        const tokenClientId = typeof rawClientId === "string" && rawClientId.length > 0
            ? rawClientId
            : typeof rawAzp === "string" && rawAzp.length > 0
                ? rawAzp
                : tokenAud;
        // Fail closed: when no owner claim (`client_id` / `azp` / `aud`) is
        // resolvable, we cannot verify ownership → treat as ownership-failure
        // (silent 200 per RFC 7009 §2.2). Matches the symmetric behavior of
        // the RT path (tryRevokeRefreshToken treats undefined azp as mismatch).
        if (tokenClientId === undefined || tokenClientId !== requestingClientId) {
            opts.logger.debug({
                scope: "oauth.revoke.access",
                expected: requestingClientId,
                got: tokenClientId ?? "<missing>",
            }, "AT revoke skipped: client_id mismatch or missing");
            return;
        }
        await opts.accessTokenDenylist.add(jti, exp * 1000);
    }
    catch {
        // Invalid signature / wrong type / wrong issuer → silent 200.
        opts.logger.debug({ scope: "oauth.revoke.access" }, "AT revoke skipped (verification failed)");
    }
}
