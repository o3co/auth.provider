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
import * as oidc from "openid-client";
import { resolveCallbackRedirect, validateRedirect } from "./helpers.mjs";
import { codeChallenge } from "./pkce.mjs";
const GOOGLE_ISSUER = "https://accounts.google.com";
const SCOPES = ["openid", "profile", "email"];
export function createGoogleProvider(config) {
    if (!config.clientId || !config.clientSecret || !config.callbackURL) {
        throw new Error(`Google federation "${config.name}" requires clientId, clientSecret, and callbackURL`);
    }
    // ServerMetadata constructed locally — no discovery call. Google's endpoints are stable.
    // Local variable type (oidc.ServerMetadata) does not survive to the .d.mts.
    const serverMetadata = {
        issuer: GOOGLE_ISSUER,
        authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
        token_endpoint: "https://oauth2.googleapis.com/token",
        userinfo_endpoint: "https://www.googleapis.com/oauth2/v3/userinfo",
    };
    const oidcConfig = new oidc.Configuration(serverMetadata, config.clientId, config.clientSecret);
    return {
        name: config.name,
        scope: SCOPES,
        validateRedirect(url) {
            return validateRedirect(url, config);
        },
        resolveCallbackRedirect(session) {
            return resolveCallbackRedirect(session, config);
        },
        buildAuthorizationUrl(params) {
            return oidc.buildAuthorizationUrl(oidcConfig, {
                redirect_uri: params.redirectUri,
                scope: SCOPES.join(" "),
                state: params.state,
                code_challenge: codeChallenge(params.codeVerifier),
                code_challenge_method: "S256",
                access_type: "offline",
            });
        },
        async exchangeCode(params) {
            // openid-client's authorizationCodeGrant expects the full callback URL.
            // We synthesize it from redirectUri + code since the route receives them separately.
            const callbackUrl = new URL(params.redirectUri);
            callbackUrl.searchParams.set("code", params.code);
            const tokens = await oidc.authorizationCodeGrant(oidcConfig, callbackUrl, {
                pkceCodeVerifier: params.codeVerifier,
                expectedState: oidc.skipStateCheck,
            });
            const userInfo = await oidc.fetchUserInfo(oidcConfig, tokens.access_token, oidc.skipSubjectCheck);
            const expiresIn = typeof tokens.expires_in === "number" ? tokens.expires_in : 3600;
            // Extension claims: anything beyond first-class fields lands on the profile
            // via the index signature — no `raw` wrapper needed.
            const profile = {
                issuer: GOOGLE_ISSUER,
                sub: typeof userInfo.sub === "string" ? userInfo.sub : "",
                email: typeof userInfo.email === "string" ? userInfo.email : undefined,
                emailVerified: typeof userInfo.email_verified === "boolean" ? userInfo.email_verified : undefined,
                name: typeof userInfo.name === "string" ? userInfo.name : undefined,
                picture: typeof userInfo.picture === "string" ? userInfo.picture : undefined,
                accessToken: tokens.access_token,
                refreshToken: typeof tokens.refresh_token === "string" ? tokens.refresh_token : undefined,
                idToken: typeof tokens.id_token === "string" ? tokens.id_token : undefined,
                expiresAt: new Date(Date.now() + expiresIn * 1000),
            };
            // Carry through known extension claims (e.g. Google hd).
            if (typeof userInfo.hd === "string") {
                profile.hd = userInfo.hd;
            }
            return profile;
        },
        async refreshToken(refreshTokenValue) {
            const tokens = await oidc.refreshTokenGrant(oidcConfig, refreshTokenValue);
            const expiresIn = typeof tokens.expires_in === "number" ? tokens.expires_in : 3600;
            return {
                accessToken: tokens.access_token,
                refreshToken: typeof tokens.refresh_token === "string" ? tokens.refresh_token : undefined,
                idToken: typeof tokens.id_token === "string" ? tokens.id_token : undefined,
                expiresAt: new Date(Date.now() + expiresIn * 1000),
                // sub / issuer intentionally absent — callers reuse stored identity.
            };
        },
        async endSession(req) {
            // Google does not publish an OIDC end_session_endpoint in its discovery document.
            // Operators MUST pass endSessionEndpoint explicitly for upstream logout.
            // Absent that, redirect directly to postLogoutRedirectUri (or accounts.google.com/Logout).
            if (config.endSessionEndpoint) {
                let url;
                try {
                    url = new URL(config.endSessionEndpoint);
                }
                catch {
                    throw new Error(`Google federation "${config.name}" has an invalid endSessionEndpoint: ${config.endSessionEndpoint}`);
                }
                if (req.idTokenHint)
                    url.searchParams.set("id_token_hint", req.idTokenHint);
                if (req.postLogoutRedirectUri)
                    url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
                if (req.state)
                    url.searchParams.set("state", req.state);
                return { url, method: "GET" };
            }
            const base = req.postLogoutRedirectUri ?? `${GOOGLE_ISSUER}/Logout`;
            let url;
            try {
                url = new URL(base);
            }
            catch {
                throw new Error(`Google federation "${config.name}" received an invalid postLogoutRedirectUri: ${base}`);
            }
            if (req.state)
                url.searchParams.set("state", req.state);
            return { url, method: "GET" };
        },
        mapClaims(profile) {
            const claims = {};
            if (typeof profile.email === "string")
                claims.email = profile.email;
            if (typeof profile.emailVerified === "boolean")
                claims.emailVerified = profile.emailVerified;
            if (typeof profile.name === "string")
                claims.name = profile.name;
            if (typeof profile.picture === "string")
                claims.picture = profile.picture;
            // Pass through extension claims (e.g. hd for Google Workspace domain restriction).
            if (typeof profile.hd === "string")
                claims.hd = profile.hd;
            return claims;
        },
    };
}
