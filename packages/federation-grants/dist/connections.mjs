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
import { identityClaimsProblem, RESERVED_DELEGATED_AUTHORIZATION_PARAMS, } from "@o3co/auth-provider-session";
/** A connection name: what appears in a key, an audit event and an operator's head. */
const NAME = /^[A-Za-z0-9_-]+$/;
/** RFC 6749 §3.3 scope-token: no space, no quote, no backslash, no control byte. */
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
const refuse = (name, what) => {
    throw new Error(`federationGrants.connections.${name}: ${what}`);
};
/**
 * The four spellings an environment variable may say a boolean in, as core's
 * schema reads them. Restated structurally rather than imported as a Zod
 * schema because this value arrives inside a `z.record`, which the HOCON
 * bridge does not descend into — so it is a string here whatever the schema
 * did elsewhere (#288).
 */
const boolean = (value, name, key) => {
    if (typeof value === "boolean")
        return value;
    const spelling = typeof value === "string" ? value.trim().toLowerCase() : undefined;
    if (spelling === "true" || spelling === "1")
        return true;
    if (spelling === "false" || spelling === "0" || spelling === "")
        return false;
    return refuse(name, `${key} must be one of "true", "false", "1" or "0"`);
};
/**
 * An absolute URI an operator wrote, kept exactly as they wrote it.
 *
 * A fragment is refused rather than dropped: a resource indicator is compared
 * for equality by the upstream, and silently normalising one changes what the
 * grant asks for.
 */
const absoluteUri = (value, name, key) => {
    if (typeof value !== "string" || value === "")
        return refuse(name, `${key} must be a URI`);
    let url;
    try {
        url = new URL(value);
    }
    catch {
        return refuse(name, `${key} must be an absolute URI, and "${value}" is not`);
    }
    if (url.hash !== "" || value.includes("#")) {
        return refuse(name, `${key} must not carry a fragment`);
    }
    // `new URL()` parses `javascript:alert(1)` perfectly happily, and userinfo
    // in a value this provider echoes to an upstream is a credential in a
    // place nobody will look for one. Review found both; `callbackURL` already
    // refused them and `resource` did not.
    if (url.protocol !== "https:" && url.protocol !== "http:") {
        return refuse(name, `${key} must be an http or https URI`);
    }
    if (url.username !== "" || url.password !== "") {
        return refuse(name, `${key} must not carry userinfo`);
    }
    return value;
};
/** HTTPS, or HTTP on a loopback host — the only place a browser may be sent back to. */
const callbackUrl = (value, name) => {
    const spelled = absoluteUri(value, name, "callbackURL");
    const url = new URL(spelled);
    const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
    if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
        return refuse(name, "callbackURL must be https, or http on a loopback host for development");
    }
    return spelled;
};
const scopes = (value, name) => {
    if (!Array.isArray(value) || value.length === 0) {
        return refuse(name, "scopes must be a non-empty list — it is the ceiling an intent asks within");
    }
    const seen = new Set();
    for (const scope of value) {
        if (typeof scope !== "string" || !SCOPE_TOKEN.test(scope)) {
            return refuse(name, `scopes must be scope tokens, and ${JSON.stringify(scope)} is not`);
        }
        if (seen.has(scope))
            return refuse(name, `scopes lists ${JSON.stringify(scope)} twice (duplicate)`);
        seen.add(scope);
    }
    if (!seen.has("openid")) {
        // Without it the upstream issues no id_token, and there is no subject
        // to pin the grant's identity to.
        return refuse(name, 'scopes must include "openid"');
    }
    // `offline_access` deliberately not required: providers differ in how they
    // are asked for a renewable credential, and Microsoft's is not Google's.
    return value;
};
const authorizationParams = (value, name) => {
    if (value === undefined)
        return {};
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        return refuse(name, "authorizationParams must be a map of strings");
    }
    for (const [key, param] of Object.entries(value)) {
        if (key === "__proto__") {
            // An own `__proto__` survives a spread and is lost to an assignment,
            // so two stores keeping the same intent would disagree about it. No
            // authorization server defines the name (Copilot).
            return refuse(name, 'authorizationParams may not set "__proto__"');
        }
        if (RESERVED_DELEGATED_AUTHORIZATION_PARAMS.has(key)) {
            // The exclusion slice 2 applies at the point of use, applied here at
            // boot: setting one of these from configuration is not customising
            // the flow, it is taking over its security parameters (D17).
            return refuse(name, `authorizationParams may not set "${key}" — this provider owns it`);
        }
        if (typeof param !== "string") {
            // A non-string would be sent spelled out, and `"undefined"` is a
            // value the upstream will happily act on.
            return refuse(name, `authorizationParams "${key}" must be a string`);
        }
    }
    return { ...value };
};
/**
 * #611: the id_token claims check 5 hands the Store. Refused at boot by the
 * adapter's own rule, so a list the adapter would refuse at the callback — a
 * name the protocol owns, a repeat — is found before a user consents.
 */
const identityClaims = (value, name) => {
    if (value === undefined)
        return [];
    if (!Array.isArray(value))
        return refuse(name, "identityClaims must be a list of claim names");
    const problem = identityClaimsProblem(value);
    if (problem !== undefined)
        return refuse(name, problem);
    return [...value];
};
/** A plain decimal, which is the only shape an operator writes a duration in. */
const DECIMAL = /^\d+$/;
/**
 * A whole positive number of seconds.
 *
 * The type is checked before the value, for the reason review gave: `Number(x)`
 * read `true` as one second and `[5]` as five, and a fraction is not something
 * an upstream's `expires_in` — whole seconds, by RFC 6749 §4.2.2 — can be
 * compared with.
 */
const seconds = (value, name, key) => {
    const parsed = typeof value === "number"
        ? value
        : typeof value === "string" && DECIMAL.test(value.trim())
            ? Number(value.trim())
            : Number.NaN;
    if (!Number.isInteger(parsed) || parsed <= 0) {
        return refuse(name, `${key} must be a whole positive number of seconds`);
    }
    return parsed;
};
/**
 * Every configured connection, joined with the federation it points at.
 *
 * An empty map is valid and so is an absent one: removing the last connection
 * has to remain an operable change, and a deployment with none still answers
 * about the grants it already has.
 */
export function resolveFederationGrantConnections(config) {
    const root = config;
    const federations = root?.federations ?? {};
    const entries = root?.federationGrants?.connections ?? {};
    const resolved = new Map();
    for (const [name, raw] of Object.entries(entries)) {
        if (name === "" || !NAME.test(name)) {
            throw new Error(`federationGrants.connections: ${JSON.stringify(name)} is not a usable connection name ` +
                "(letters, digits, underscore and hyphen)");
        }
        if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
            refuse(name, "must be a configuration block");
        }
        const entry = raw;
        const federation = entry.federation;
        if (typeof federation !== "string" || federation === "") {
            refuse(name, "federation must name a configured federation");
        }
        const upstream = federations[federation];
        if (upstream === undefined) {
            refuse(name, `federation "${federation}" is not configured`);
        }
        if (boolean(upstream.enabled, name, `federations.${federation}.enabled`) !== true) {
            refuse(name, `federation "${federation}" is configured but disabled`);
        }
        // Configured, never discovered: this pair is persisted into the grant's
        // identity revision, and a fingerprint that moves when an IdP edits its
        // metadata would retire every grant on that connection.
        if (typeof upstream.issuer !== "string" || upstream.issuer === "") {
            refuse(name, `federations.${federation}.issuer must be configured — a grant's identity is pinned to it, ` +
                "so it has to be a value an operator can see and change");
        }
        if (typeof upstream.clientId !== "string" || upstream.clientId === "") {
            refuse(name, `federations.${federation}.clientId must be configured`);
        }
        const boundary = entry.boundary;
        if (typeof boundary !== "string" || boundary === "") {
            // Required, so that isolation between environments is not opt-in
            // (D13): a boundary nobody set is a boundary everything shares.
            refuse(name, "boundary must name the environment this connection belongs to");
        }
        resolved.set(name, {
            name,
            federation: federation,
            upstreamIssuer: upstream.issuer,
            upstreamClientId: upstream.clientId,
            scopes: scopes(entry.scopes, name),
            boundary: boundary,
            maxAccessTokenLifetime: seconds(entry.maxAccessTokenLifetime, name, "maxAccessTokenLifetime"),
            allowScopeSubsets: entry.allowScopeSubsets === undefined
                ? true
                : boolean(entry.allowScopeSubsets, name, "allowScopeSubsets"),
            authorizationParams: authorizationParams(entry.authorizationParams, name),
            identityClaims: identityClaims(entry.identityClaims, name),
            ...(entry.resource === undefined
                ? {}
                : { resource: absoluteUri(entry.resource, name, "resource") }),
            // Optional here — a worker spending a grant never performs the browser
            // flow — and required by acquisition, which refuses at boot a connection
            // that lacks one (`acquisitionSettings.mts`).
            ...(entry.callbackURL === undefined
                ? {}
                : { callbackUri: callbackUrl(entry.callbackURL, name) }),
        });
    }
    return resolved;
}
