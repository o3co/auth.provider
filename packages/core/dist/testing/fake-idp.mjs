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
import { createHash } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { readSpaceDelimitedParameter } from "../federations/scope.mjs";
/** The defaults with the overlay laid over them, and every field the overlay set to `undefined` gone. */
const overlaid = (defaults, overlay) => Object.fromEntries(Object.entries({ ...defaults, ...overlay }).filter(([, value]) => value !== undefined));
function json(body, status = 200) {
    return new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
    });
}
/**
 * Where a request goes: origin and path, the host without the DNS root dot.
 * `idp.test.` and `idp.test` resolve to the same server, so a request that
 * carries the dot reaches this IdP too.
 */
const originAndPath = (url) => {
    const routed = new URL(url.href);
    routed.hostname = routed.hostname.replace(/\.$/, "");
    return `${routed.origin}${routed.pathname}`;
};
/** OIDC Core §3.3.2.11 for an RS256 id_token: SHA-256, left half, base64url. */
const sha256LeftHalf = (value) => {
    const digest = createHash("sha256").update(value).digest();
    return digest.subarray(0, digest.length / 2).toString("base64url");
};
export async function createFakeIdp(options) {
    const issuer = options.issuer.replace(/\/$/, "");
    const clientId = options.clientId ?? "client-under-test";
    const sub = options.sub ?? "user-0001";
    const urls = {
        authorization: options.authorizationEndpoint ?? `${issuer}/authorize`,
        token: options.tokenEndpoint ?? `${issuer}/token`,
        jwks: options.jwksUri ?? `${issuer}/jwks`,
        userinfo: options.userinfoEndpoint,
        discovery: `${issuer}/.well-known/openid-configuration`,
    };
    const endpoints = {
        authorization: originAndPath(new URL(urls.authorization)),
        token: originAndPath(new URL(urls.token)),
        jwks: originAndPath(new URL(urls.jwks)),
        userinfo: urls.userinfo === undefined ? undefined : originAndPath(new URL(urls.userinfo)),
        discovery: options.discovery ? originAndPath(new URL(urls.discovery)) : undefined,
    };
    /** A path under the issuer (`"/token"`) or an absolute URL, as the endpoint it names. */
    const endpointOf = (endpoint) => originAndPath(new URL(endpoint.startsWith("/") ? `${issuer}${endpoint}` : endpoint));
    const metadata = {
        issuer,
        authorization_endpoint: urls.authorization,
        token_endpoint: urls.token,
        jwks_uri: urls.jwks,
        ...(urls.userinfo === undefined ? {} : { userinfo_endpoint: urls.userinfo }),
        ...(options.endSessionEndpoint === undefined
            ? {}
            : { end_session_endpoint: options.endSessionEndpoint }),
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        token_endpoint_auth_methods_supported: ["client_secret_basic", "private_key_jwt"],
        code_challenge_methods_supported: ["S256"],
    };
    /** The authorization request behind each code `authorize` issued, until it is exchanged. */
    const authorizations = new Map();
    /** Codes `authorize` issued that have been exchanged: a second exchange is refused. */
    const spentCodes = new Set();
    let codesIssued = 0;
    /** Whether this client has been granted consent by this user before. */
    let consentGranted = false;
    let keyIndex = 0;
    let signer = { kid: "", key: undefined };
    const jwks = { keys: [] };
    const newKey = async () => {
        const { publicKey, privateKey } = await generateKeyPair("RS256");
        keyIndex += 1;
        const kid = `kid-${keyIndex}`;
        jwks.keys = [{ ...(await exportJWK(publicKey)), kid, use: "sig", alg: "RS256" }];
        signer = { kid, key: privateKey };
        return kid;
    };
    await newKey();
    const requests = [];
    const requestsTo = (endpoint) => {
        const wanted = endpointOf(endpoint);
        return requests.filter((r) => originAndPath(r.url) === wanted);
    };
    const idp = {
        issuer,
        clientId,
        sub,
        requests,
        metadata,
        discoveryStatus: 200,
        idTokenClaims: {},
        nonce: undefined,
        signingKid: undefined,
        signWithUnpublishedKey: false,
        omitIdToken: false,
        refreshWithIdToken: true,
        atHash: "none",
        userinfoClaims: {},
        tokenStatus: 200,
        refusal: { error: "invalid_client" },
        accessToken: "at-1",
        codeAnswer: {},
        refreshAnswer: {},
        jwksDelayMs: 0,
        refreshTokenOnlyOnConsent: false,
        authorize: (input) => {
            const url = new URL(input);
            if (originAndPath(url) !== endpoints.authorization) {
                throw new Error(`fake IdP: ${originAndPath(url)} is not its authorization endpoint`);
            }
            const params = url.searchParams;
            if (params.get("client_id") !== clientId) {
                throw new Error(`fake IdP: unknown client_id ${String(params.get("client_id"))}`);
            }
            // OIDC Core §3.1.2.1: space-delimited. Read as a real IdP reads it, and
            // refused when it is not, so an adapter that sent a malformed prompt
            // fails here rather than only against a real IdP.
            const prompts = readSpaceDelimitedParameter(params.get("prompt") ?? "");
            if (prompts === null) {
                throw new Error(`fake IdP: prompt ${JSON.stringify(params.get("prompt"))} is not a space-delimited list`);
            }
            const consentShown = !consentGranted || prompts.includes("consent");
            consentGranted = true;
            codesIssued += 1;
            const code = `authorized-code-${codesIssued}`;
            authorizations.set(code, { params: new URLSearchParams(params), consentShown });
            return { code, state: params.get("state"), iss: issuer };
        },
        fetch: undefined,
        rotateKey: newKey,
        currentKid: () => signer.kid,
        requestsTo,
        lastTokenRequest: () => requestsTo(urls.token).at(-1),
    };
    /**
     * A refresh's id_token carries no nonce: there is no authorization request
     * for it to echo. A code's carries the nonce of the authorization it came
     * from, or — for a code `authorize` did not issue — `idp.nonce`. `at_hash`
     * binds the code exchange's access token.
     */
    const mintIdToken = async (opts = { nonce: true }) => {
        const nonce = opts.authorizedNonce !== undefined ? opts.authorizedNonce : idp.nonce;
        const now = Math.floor(Date.now() / 1000);
        const claims = {
            iss: issuer,
            aud: clientId,
            sub,
            iat: now,
            exp: now + 300,
            email: "alice@example.test",
            email_verified: true,
            name: "Alice Example",
            ...(opts.nonce && nonce !== undefined && nonce !== null ? { nonce } : {}),
            ...(opts.accessToken === undefined || idp.atHash === "none"
                ? {}
                : {
                    at_hash: idp.atHash === "valid" ? sha256LeftHalf(opts.accessToken) : "AAAAAAAAAAAAAAAAAAAAAA",
                }),
            ...idp.idTokenClaims,
        };
        const key = idp.signWithUnpublishedKey
            ? (await generateKeyPair("RS256")).privateKey
            : signer.key;
        return new SignJWT(claims)
            .setProtectedHeader({ alg: "RS256", kid: idp.signingKid ?? signer.kid })
            .sign(key);
    };
    const fetchImpl = async (input, init) => {
        const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
        const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
        const headers = new Headers((init?.headers ??
            (input instanceof Request ? input.headers : undefined)));
        const raw = init?.body;
        const body = raw === undefined || raw === null
            ? undefined
            : new URLSearchParams(raw instanceof URLSearchParams ? raw : String(raw));
        requests.push({ url, method, headers, body });
        const where = originAndPath(url);
        if (endpoints.discovery !== undefined && where === endpoints.discovery) {
            return json(metadata, idp.discoveryStatus);
        }
        if (where === endpoints.jwks) {
            if (idp.jwksDelayMs > 0)
                await new Promise((resolve) => setTimeout(resolve, idp.jwksDelayMs));
            return json(jwks);
        }
        if (where === endpoints.token && method === "POST") {
            if (idp.tokenStatus !== 200)
                return json(idp.refusal, idp.tokenStatus);
            if (body?.get("grant_type") === "refresh_token") {
                return json(overlaid({
                    access_token: "at-refreshed",
                    token_type: "Bearer",
                    expires_in: 1800,
                    refresh_token: "rt-2",
                    ...(idp.omitIdToken || !idp.refreshWithIdToken
                        ? {}
                        : { id_token: await mintIdToken({ nonce: false }) }),
                }, idp.refreshAnswer));
            }
            const code = body?.get("code") ?? "";
            if (spentCodes.has(code))
                return json({ error: "invalid_grant" }, 400);
            const authorization = authorizations.get(code);
            let issueRefreshToken = true;
            if (authorization !== undefined) {
                // One use, the same redirect URI, and a verifier that matches the
                // challenge (RFC 6749 §4.1.3, RFC 7636 §4.6).
                authorizations.delete(code);
                spentCodes.add(code);
                const challenge = createHash("sha256")
                    .update(body?.get("code_verifier") ?? "")
                    .digest("base64url");
                if (body?.get("redirect_uri") !== authorization.params.get("redirect_uri") ||
                    challenge !== authorization.params.get("code_challenge")) {
                    return json({ error: "invalid_grant" }, 400);
                }
                if (idp.refreshTokenOnlyOnConsent) {
                    issueRefreshToken =
                        authorization.params.get("access_type") === "offline" && authorization.consentShown;
                }
            }
            return json(overlaid({
                access_token: idp.accessToken,
                token_type: "Bearer",
                expires_in: 3600,
                ...(issueRefreshToken ? { refresh_token: "rt-1" } : {}),
                ...(idp.omitIdToken
                    ? {}
                    : {
                        id_token: await mintIdToken({
                            nonce: true,
                            ...(authorization !== undefined
                                ? { authorizedNonce: authorization.params.get("nonce") }
                                : {}),
                            accessToken: idp.accessToken,
                        }),
                    }),
            }, idp.codeAnswer));
        }
        if (endpoints.userinfo !== undefined && where === endpoints.userinfo) {
            return json({
                sub,
                email: "alice@example.test",
                email_verified: true,
                name: "Alice Example",
                picture: `${issuer}/alice.png`,
                ...idp.userinfoClaims,
            });
        }
        return new Response("not found", { status: 404 });
    };
    idp.fetch = fetchImpl;
    return idp;
}
