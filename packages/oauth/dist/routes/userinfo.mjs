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
import { filterClaimsByScope, } from "@o3co/auth-provider-core";
import { decodeProtectedHeader, jwtVerify } from "jose";
/**
 * OIDC Core §5.3 — UserInfo Endpoint.
 *
 * Accepts Bearer access_token JWTs and returns scope-filtered claims from
 * the durable UserSession. Revocation is checked via family_id (cascade
 * revoke per F-3) and sid (session liveness).
 *
 * Error responses follow Bearer Token Usage (RFC 6750 §3.1): 401 with
 * WWW-Authenticate header. Fail-closed on store errors.
 */
export function createRouter(express, opts) {
    const router = express.Router();
    router.get("/userinfo", async (req, res) => {
        // RFC 6750 §5.3 + §6.1: bearer-authenticated responses MUST NOT be cached
        // by intermediaries. Set this once at the top so it applies to every
        // response path (200 success, 401 error).
        res.setHeader("Cache-Control", "no-store");
        res.setHeader("Pragma", "no-cache");
        // RFC 6750 §2.1: Bearer token in Authorization header
        const auth = req.headers.authorization;
        if (!auth?.startsWith("Bearer ")) {
            res.setHeader("WWW-Authenticate", 'Bearer realm="userinfo"');
            return res
                .status(401)
                .json({ error: "invalid_token", error_description: "missing Bearer token" });
        }
        const token = auth.slice(7);
        // Verify JWT signature + reject non-access tokens. Refresh tokens
        // (typ: rt+jwt) and id_tokens (typ: id+jwt) are signed by the same
        // KeyStore and carry sub/sid/scope claims, so without a typ check
        // they would also pass signature verification here. RFC 9068
        // establishes `typ: "at+jwt"` as the indicator that a JWT is
        // specifically an OAuth 2.0 access token; userinfo is an access-token
        // resource (OIDC Core §5.3.1), so we require that typ exactly.
        let payload;
        try {
            const header = decodeProtectedHeader(token);
            if (header.typ !== "at+jwt") {
                throw new Error("invalid token type");
            }
            const key = await opts.keyStore.getVerificationKey(header.kid ?? opts.keyStore.getSigningKidFallback());
            const verified = await jwtVerify(token, key);
            payload = verified.payload;
        }
        catch {
            res.setHeader("WWW-Authenticate", 'Bearer realm="userinfo", error="invalid_token"');
            return res.status(401).json({ error: "invalid_token", error_description: "invalid token" });
        }
        // F-3 cascade revoke: check family_id against RefreshTokenStore.
        // Precondition: only activates when the JWT carries a family_id claim —
        // tokens minted before F-3 lack this claim and bypass the cascade check
        // (legacy backward-compat). New tokens always carry family_id per F-3.
        const familyId = typeof payload.family_id === "string" ? payload.family_id : null;
        if (familyId !== null && opts.refreshTokenStore) {
            let revoked;
            try {
                revoked = await opts.refreshTokenStore.isFamilyRevoked(familyId);
            }
            catch {
                // Fail-closed: cannot determine revocation state → treat as revoked
                res.setHeader("WWW-Authenticate", 'Bearer realm="userinfo", error="invalid_token"');
                return res
                    .status(401)
                    .json({ error: "invalid_token", error_description: "revocation check unavailable" });
            }
            if (revoked) {
                res.setHeader("WWW-Authenticate", 'Bearer realm="userinfo", error="invalid_token"');
                return res
                    .status(401)
                    .json({ error: "invalid_token", error_description: "family revoked" });
            }
        }
        // sub is required; sid is optional (needed for session-backed claims —
        // when absent or no userSessionStore wired, we return {sub} only).
        const sub = typeof payload.sub === "string" ? payload.sub : null;
        const sid = typeof payload.sid === "string" ? payload.sid : null;
        if (!sub) {
            res.setHeader("WWW-Authenticate", 'Bearer realm="userinfo", error="invalid_token"');
            return res
                .status(401)
                .json({ error: "invalid_token", error_description: "missing sub claim" });
        }
        // Without a session store, return only sub (no durable claim source)
        if (!opts.userSessionStore || !sid) {
            return res.status(200).json({ sub });
        }
        // Validate session liveness. Fail-closed on store throw (symmetric with
        // the refreshTokenStore cascade above): a backend outage must not leak
        // claims, and returning 401 invalid_token keeps parity with RFC 6750.
        let session;
        try {
            session = await opts.userSessionStore.get(sid);
        }
        catch {
            res.setHeader("WWW-Authenticate", 'Bearer realm="userinfo", error="invalid_token"');
            return res
                .status(401)
                .json({ error: "invalid_token", error_description: "session lookup unavailable" });
        }
        if (!session) {
            res.setHeader("WWW-Authenticate", 'Bearer realm="userinfo", error="invalid_token"');
            return res.status(401).json({ error: "invalid_token", error_description: "session_invalid" });
        }
        // Return sub + scope-filtered claims per OIDC Core §5.4
        const scopes = typeof payload.scope === "string" ? payload.scope.split(" ").filter(Boolean) : [];
        const filtered = filterClaimsByScope(session.claims, scopes);
        return res.status(200).json({ sub, ...filtered });
    });
    return router;
}
