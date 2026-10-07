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
import { defineModule, isLoopbackHostname } from "@o3co/auth-provider-core";
import { codeChallenge, createFederationRedirectPolicy, resolveClientSecret, } from "@o3co/auth-provider-session";
import * as oidc from "openid-client";
import { createAppleClientSecret } from "./client-secret.mjs";
export const APPLE_ISSUER = "https://appleid.apple.com";
const APPLE_JWKS_URI = "https://appleid.apple.com/auth/keys";
/**
 * Apple's documented scope values are `name` and `email` — and requesting
 * either is exactly what makes Apple deliver the callback as a form POST.
 * `openid` is not among the values Apple documents, so it is not sent; the
 * authorization-code flow returns an id_token regardless.
 */
const SCOPES = ["name", "email"];
/** The domain of a Hide My Email relay address. */
export const APPLE_PRIVATE_RELAY_DOMAIN = "privaterelay.appleid.com";
/**
 * Whether an address is an Apple Hide My Email relay.
 *
 * Exact-domain match, case-insensitive. A suffix test would accept
 * `privaterelay.appleid.com.attacker.example`, which is a domain an attacker
 * can register.
 */
export function isPrivateRelayEmail(email) {
    const at = email.lastIndexOf("@");
    if (at < 0)
        return false;
    return email.slice(at + 1).toLowerCase() === APPLE_PRIVATE_RELAY_DOMAIN;
}
/**
 * Read a claim Apple sends as either a boolean or the *string* `"true"` /
 * `"false"`.
 *
 * `email_verified` and `is_private_email` both arrive either way depending on
 * the response. `Boolean("false")` is `true`, so a coercion here would report
 * an unverified address as verified — the normalisation is not cosmetic.
 * Anything that is neither shape reads as absent, because absence is not
 * `false` (#297).
 */
const normalizeBooleanClaim = (value) => {
    if (typeof value === "boolean")
        return value;
    if (value === "true")
        return true;
    if (value === "false")
        return false;
    return undefined;
};
/**
 * Read the display name out of the `user` field Apple POSTs on the *first*
 * authorization only.
 *
 * The value is a JSON string relayed through the user agent, so it is parsed
 * defensively and never allowed to fail a login: a malformed or unexpectedly
 * shaped body yields no name, not an error. It is also unsigned — the route
 * layer's `state` check binds it to this session and nothing more — so what
 * comes back is self-asserted and reaches the claims envelope only under the
 * ordinary promotion rules.
 */
const parseUserName = (raw) => {
    if (typeof raw !== "string" || raw.length === 0)
        return undefined;
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
        return undefined;
    }
    if (parsed == null || typeof parsed !== "object")
        return undefined;
    const name = parsed.name;
    if (name == null || typeof name !== "object")
        return undefined;
    const { firstName, lastName } = name;
    const parts = [firstName, lastName].filter((part) => typeof part === "string" && part.length > 0);
    return parts.length > 0 ? parts.join(" ") : undefined;
};
/**
 * Resolve the one client-secret source this config declares.
 *
 * Exactly one of the two forms, checked at construction: a deployment that
 * supplies both has two answers to "which key signs this?", and a deployment
 * that supplies neither has none. Either is a boot-time misconfiguration and
 * belongs at boot, not at the first login attempt.
 */
function resolveSecretSource(config) {
    const hasKeyMaterial = config.teamId != null || config.keyId != null || config.privateKey != null;
    const hasClientSecret = config.clientSecret != null;
    if (hasClientSecret && hasKeyMaterial) {
        throw new Error(`Apple federation "apple" takes either a clientSecret or teamId/keyId/privateKey, not both`);
    }
    if (hasClientSecret) {
        return config.clientSecret;
    }
    if (!hasKeyMaterial) {
        throw new Error(`Apple federation "apple" requires a clientSecret, or teamId + keyId + privateKey to sign one`);
    }
    // `createAppleClientSecret` names whichever piece is missing.
    return createAppleClientSecret({
        teamId: config.teamId,
        clientId: config.clientId,
        keyId: config.keyId,
        privateKey: config.privateKey,
    });
}
export function createAppleProvider(config) {
    if (!config.clientId) {
        throw new Error(`Apple federation "apple" requires clientId (the Services ID)`);
    }
    if (!config.callbackURL) {
        throw new Error(`Apple federation "apple" requires callbackURL`);
    }
    // Apple's return URL is checked here, at boot, because every way it can be
    // wrong produces the same opaque `invalid_request` from the authorization
    // endpoint at the worst possible moment — the first login attempt.
    let callbackUrl;
    try {
        callbackUrl = new URL(config.callbackURL);
    }
    catch {
        throw new Error(`Apple federation "apple" received a callbackURL that is not a URL: ${config.callbackURL}`);
    }
    if (callbackUrl.protocol !== "https:") {
        throw new Error(`Apple federation "apple" requires an https callbackURL — Apple refuses a plain-http return URL (got ${config.callbackURL})`);
    }
    // `https` is necessary and not sufficient: Apple refuses a loopback return
    // URL whatever its scheme, so `https://localhost/cb` clears the check above
    // and still fails upstream. `isLoopbackHostname` is the repo's one
    // definition of that vocabulary (#364, `core/src/net/loopback.mts`) — the
    // same predicate `checkRedirectShape` uses to carve `http://` *in* for local
    // development, used here to carve loopback *out*. `localhost` is a separate
    // name from the IP literals and the predicate covers both, along with the
    // whole 127.0.0.0/8 block and bracketed `[::1]` as `URL.hostname` reports it.
    if (isLoopbackHostname(callbackUrl.hostname)) {
        throw new Error(`Apple federation "apple" refuses a loopback callbackURL (${config.callbackURL}) — Apple rejects localhost, 127.0.0.0/8 and [::1] return URLs even over https, so local development needs a tunnel or a dev hostname holding a certificate`);
    }
    const clientSecret = resolveSecretSource(config);
    // ServerMetadata constructed locally — no discovery call. Apple's endpoints
    // are stable, and Apple publishes no `userinfo_endpoint` and no
    // `end_session_endpoint`, so neither appears here.
    //
    // `jwks_uri` is required for id_token signature verification; without it
    // openid-client treats id_tokens as opaque (silent verification skip). The
    // `id_token_signing_alg_values_supported` list pins RS256 — what Apple
    // signs with — so the library refuses `none` / `HS256` confusion attacks.
    const serverMetadata = {
        issuer: APPLE_ISSUER,
        authorization_endpoint: "https://appleid.apple.com/auth/authorize",
        token_endpoint: "https://appleid.apple.com/auth/token",
        jwks_uri: config.jwksUri ?? APPLE_JWKS_URI,
        id_token_signing_alg_values_supported: ["RS256"],
    };
    // Building an authorization URL needs no client authentication, so this
    // configuration carries no secret and never triggers the ES256 signature.
    const authorizationConfig = new oidc.Configuration(serverMetadata, config.clientId);
    /**
     * A configuration for one token-endpoint call, with the secret resolved now.
     *
     * Rebuilt per call rather than once at construction because the secret
     * rotates: freezing it into a Configuration is exactly the bug that makes a
     * deployment stop authenticating six months after it was set up. Apple
     * requires `client_secret_post`, which is stated rather than inherited from
     * the library's default.
     */
    const tokenConfiguration = async () => {
        const secret = await resolveClientSecret(clientSecret);
        return new oidc.Configuration(serverMetadata, config.clientId, secret, oidc.ClientSecretPost(secret));
    };
    const requireNonce = (nonce) => {
        if (typeof nonce !== "string" || nonce.length === 0) {
            throw new Error(`Apple federation "apple" requires a non-empty nonce — OIDC §3.1.3.7 nonce binding is mandatory.`);
        }
        return nonce;
    };
    return {
        name: "apple",
        scope: SCOPES,
        // Apple POSTs the callback whenever `scope` includes `name` or `email`,
        // which SCOPES always does. The route layer reads this to send
        // `response_mode=form_post` upstream, to accept the POST callback, and to
        // mark this federation's state cookie SameSite=None; Secure.
        responseMode: "form_post",
        buildAuthorizationUrl(params) {
            const nonce = requireNonce(params.nonce);
            return oidc.buildAuthorizationUrl(authorizationConfig, {
                redirect_uri: params.redirectUri,
                scope: SCOPES.join(" "),
                state: params.state,
                code_challenge: codeChallenge(params.codeVerifier),
                code_challenge_method: "S256",
                nonce,
            });
        },
        async exchangeCode(params) {
            const nonce = requireNonce(params.nonce);
            // openid-client's authorizationCodeGrant expects the full callback URL.
            // Apple POSTs the parameters rather than putting them in a redirect, so
            // there is no such URL to hand it — it is synthesized from the
            // registered return URL plus the code, exactly as the Google adapter
            // does for a query-mode callback.
            const callbackUrl = new URL(params.redirectUri);
            callbackUrl.searchParams.set("code", params.code);
            // `expectedNonce` activates openid-client's nonce check (OIDC §3.1.3.7)
            // and also asserts an id_token is present in the response.
            const tokens = await oidc.authorizationCodeGrant(await tokenConfiguration(), callbackUrl, {
                pkceCodeVerifier: params.codeVerifier,
                expectedState: oidc.skipStateCheck,
                expectedNonce: nonce,
            });
            // Apple publishes no userinfo endpoint: the verified id_token is the
            // only source of identity, so there is no UserInfo/id_token binding to
            // make (PB-5 does not apply) and nothing to fetch.
            const claims = tokens.claims();
            const sub = claims?.sub;
            if (typeof sub !== "string" || sub.length === 0) {
                throw new Error(`Apple federation "apple" id_token is missing the sub claim`);
            }
            const email = typeof claims?.email === "string" ? claims.email : undefined;
            // Apple's own marker wins; the relay domain answers only when Apple
            // said nothing, so a real address is never mislabelled by inference.
            const isPrivateEmail = normalizeBooleanClaim(claims?.is_private_email) ??
                (email !== undefined ? isPrivateRelayEmail(email) : undefined);
            const expiresIn = typeof tokens.expires_in === "number" ? tokens.expires_in : 3600;
            const profile = {
                issuer: APPLE_ISSUER,
                sub,
                email,
                emailVerified: normalizeBooleanClaim(claims?.email_verified),
                // The name exists in the first authorization's POST body and nowhere
                // else — never in the id_token, and never again on a later login.
                name: parseUserName(params.callbackParams?.user),
                accessToken: tokens.access_token,
                refreshToken: typeof tokens.refresh_token === "string" ? tokens.refresh_token : undefined,
                idToken: typeof tokens.id_token === "string" ? tokens.id_token : undefined,
                expiresAt: new Date(Date.now() + expiresIn * 1000),
            };
            if (isPrivateEmail !== undefined) {
                profile.isPrivateEmail = isPrivateEmail;
            }
            return profile;
        },
        async refreshToken(refreshTokenValue) {
            const tokens = await oidc.refreshTokenGrant(await tokenConfiguration(), refreshTokenValue);
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
            // Apple publishes no OIDC end_session_endpoint — the same situation
            // the Google module documents, minus Google's fallback: there is no
            // appleid.apple.com logout URL to send a browser to. So an operator
            // either supplies an endpoint, or the request resolves to the
            // deployment's own post-logout page, or it fails loudly rather than
            // redirecting somewhere invented.
            if (config.endSessionEndpoint) {
                let url;
                try {
                    url = new URL(config.endSessionEndpoint);
                }
                catch {
                    throw new Error(`Apple federation "apple" has an invalid endSessionEndpoint: ${config.endSessionEndpoint}`);
                }
                if (req.idTokenHint)
                    url.searchParams.set("id_token_hint", req.idTokenHint);
                if (req.postLogoutRedirectUri)
                    url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
                if (req.state)
                    url.searchParams.set("state", req.state);
                return { url, method: "GET" };
            }
            if (!req.postLogoutRedirectUri) {
                throw new Error(`Apple federation "apple" cannot start an upstream logout: Apple publishes no end_session_endpoint, so either configure endSessionEndpoint or pass postLogoutRedirectUri`);
            }
            let url;
            try {
                url = new URL(req.postLogoutRedirectUri);
            }
            catch {
                throw new Error(`Apple federation "apple" received an invalid postLogoutRedirectUri: ${req.postLogoutRedirectUri}`);
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
            // Apple extension: whether the address is a Hide My Email relay.
            // Recorded under `claims.federated.apple` (never promoted) so a
            // deployment that must reach a real inbox can decide what to do.
            if (typeof profile.isPrivateEmail === "boolean")
                claims.isPrivateEmail = profile.isPrivateEmail;
            return claims;
        },
    };
}
/**
 * Const Module for the Sign in with Apple federation integration.
 *
 * Contributes both `federations.apple` (FederationProvider — upstream OIDC
 * protocol) and `federationRedirectPolicies.apple` (FederationRedirectPolicy
 * — consumer redirect URL policy), the pairing A5 §6 requires.
 *
 * Config arrives through the `appleFederationConfig` ComponentMap slot (per
 * A5 §10.1 const-Module pattern). Single-tenant, as the Google and GitHub
 * modules are: the federation is registered under the name "apple".
 */
export const appleFederationModule = defineModule({
    name: "federation:apple",
    requires: ["appleFederationConfig"],
    contributes: {
        federations: {
            apple: (deps) => createAppleProvider(deps.appleFederationConfig),
        },
        federationRedirectPolicies: {
            apple: (deps) => createFederationRedirectPolicy(deps.appleFederationConfig),
        },
    },
});
