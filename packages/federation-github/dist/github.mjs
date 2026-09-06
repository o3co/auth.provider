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
import { defineModule } from "@o3co/auth-provider-core";
import { codeChallenge, createFederationRedirectPolicy, } from "@o3co/auth-provider-session";
import * as oidc from "openid-client";
const GITHUB_ISSUER = "https://github.com";
const SCOPES = ["read:user", "user:email"];
const GITHUB_EMAILS_URL = "https://api.github.com/user/emails";
export function createGithubProvider(config) {
    if (!config.clientId || !config.clientSecret || !config.callbackURL) {
        throw new Error(`GitHub federation "github" requires clientId, clientSecret, and callbackURL`);
    }
    // GitHub does not expose an OIDC discovery document, so we construct ServerMetadata manually.
    // Local variable type (oidc.ServerMetadata) does not survive to the .d.mts.
    const serverMetadata = {
        issuer: GITHUB_ISSUER,
        authorization_endpoint: "https://github.com/login/oauth/authorize",
        token_endpoint: "https://github.com/login/oauth/access_token",
        userinfo_endpoint: "https://api.github.com/user",
    };
    const oidcConfig = new oidc.Configuration(serverMetadata, config.clientId, config.clientSecret);
    return {
        name: "github",
        scope: SCOPES,
        buildAuthorizationUrl(params) {
            return oidc.buildAuthorizationUrl(oidcConfig, {
                redirect_uri: params.redirectUri,
                scope: SCOPES.join(" "),
                state: params.state,
                code_challenge: codeChallenge(params.codeVerifier),
                code_challenge_method: "S256",
            });
        },
        async exchangeCode(params) {
            // Synthesize the callback URL from redirectUri + code.
            const callbackUrl = new URL(params.redirectUri);
            callbackUrl.searchParams.set("code", params.code);
            const tokens = await oidc.authorizationCodeGrant(oidcConfig, callbackUrl, {
                pkceCodeVerifier: params.codeVerifier,
                expectedState: oidc.skipStateCheck,
            });
            const userInfo = await oidc.fetchUserInfo(oidcConfig, tokens.access_token, oidc.skipSubjectCheck);
            // GitHub's /user endpoint returns `id: number`, not the OIDC `sub` field.
            // openid-client passes the raw JSON through without remapping id → sub.
            // Coerce to string so every profile has a stable, non-empty sub.
            const ghId = userInfo.id;
            const sub = typeof userInfo.sub === "string" && userInfo.sub !== ""
                ? userInfo.sub
                : typeof ghId === "number"
                    ? String(ghId)
                    : typeof ghId === "string" && ghId !== ""
                        ? ghId
                        : "";
            if (!sub) {
                throw new Error(`GitHub federation "github" received userinfo without id/sub`);
            }
            // Fetch primary+verified email from /user/emails.
            // GitHub's /user endpoint often omits email for users who keep it private.
            // Fallback order:
            //   1. primary + verified email
            //   2. first verified email (when primary is unverified)
            //   3. undefined (no verified email at all)
            let email;
            let emailVerified;
            try {
                const emailsRes = await oidc.fetchProtectedResource(oidcConfig, tokens.access_token, new URL(GITHUB_EMAILS_URL), "GET");
                const rows = (await emailsRes.json());
                if (Array.isArray(rows)) {
                    const verified = rows.filter((r) => r.verified === true && typeof r.email === "string");
                    const primary = verified.find((r) => r.primary === true);
                    const chosen = primary ?? verified[0];
                    if (chosen && typeof chosen.email === "string") {
                        email = chosen.email;
                        emailVerified = true;
                    }
                }
            }
            catch {
                // Transient /user/emails failure treated as "no email available" — never kills login.
            }
            const expiresIn = typeof tokens.expires_in === "number" ? tokens.expires_in : undefined;
            // GitHub's /user returns `avatar_url` (not the OIDC `picture` field).
            const ghAvatarUrl = userInfo.avatar_url;
            return {
                issuer: GITHUB_ISSUER,
                sub,
                email,
                emailVerified,
                name: typeof userInfo.name === "string" ? userInfo.name : undefined,
                picture: typeof ghAvatarUrl === "string" ? ghAvatarUrl : undefined,
                accessToken: tokens.access_token,
                // GitHub OAuth Apps do not issue refresh tokens.
                refreshToken: undefined,
                // GitHub OAuth Apps classic tokens have no finite expiry; the new-style
                // user-to-server tokens (`expires_in`-bearing) do. `null` signals "reuse,
                // do not attempt refresh" — see FederationProfile.expiresAt contract.
                expiresAt: expiresIn !== undefined ? new Date(Date.now() + expiresIn * 1000) : null,
            };
        },
        // GitHub has no RP-Initiated Logout endpoint by default.
        // Precedence: (1) configured endSessionEndpoint wins; (2) postLogoutRedirectUri redirect;
        // (3) fallback to https://github.com/logout (preserves pre-Task-3 behaviour, supports GitHub Enterprise).
        async endSession(req) {
            if (config.endSessionEndpoint) {
                let url;
                try {
                    url = new URL(config.endSessionEndpoint);
                }
                catch {
                    throw new Error(`GitHub federation "github" has an invalid endSessionEndpoint: ${config.endSessionEndpoint}`);
                }
                if (req.idTokenHint)
                    url.searchParams.set("id_token_hint", req.idTokenHint);
                if (req.postLogoutRedirectUri)
                    url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
                if (req.state)
                    url.searchParams.set("state", req.state);
                return { url, method: "GET" };
            }
            const base = req.postLogoutRedirectUri ?? `${GITHUB_ISSUER}/logout`;
            let url;
            try {
                url = new URL(base);
            }
            catch {
                throw new Error(`GitHub federation "github" received an invalid postLogoutRedirectUri: ${base}`);
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
            return claims;
        },
    };
}
/**
 * Const Module for the GitHub federation integration.
 *
 * Contributes both `federations.github` (FederationProvider — upstream OAuth 2
 * protocol) and `federationRedirectPolicies.github` (FederationRedirectPolicy
 * — consumer redirect URL policy).
 *
 * Config supplied via the `githubFederationConfig` ComponentMap slot
 * (per A5 §10.2 const-Module pattern).
 *
 * Per A5 §10.2.
 */
export const githubFederationModule = defineModule({
    name: "federation:github",
    requires: ["githubFederationConfig"],
    contributes: {
        federations: {
            // v0.5.0 is single-tenant: provider.name is fixed at "github".
            // Multi-tenant support deferred to post-publish; consumers needing
            // multiple GitHub apps will get an additive Config shape.
            github: (deps) => createGithubProvider(deps.githubFederationConfig),
        },
        federationRedirectPolicies: {
            github: (deps) => createFederationRedirectPolicy(deps.githubFederationConfig),
        },
    },
});
