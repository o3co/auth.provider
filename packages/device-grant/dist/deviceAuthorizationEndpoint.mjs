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
import { generateDeviceCode, generateUserCode, isGrantTypeAllowed, normaliseUserCode, } from "@o3co/auth-provider-core";
import { DEVICE_CODE_GRANT_TYPE } from "./types.mjs";
const fail = (res, status, body) => {
    // RFC 6749 §5.2 cache directives: an error naming a client_id must not be
    // held by an intermediary and replayed to someone else.
    res.status(status).set("Cache-Control", "no-store").set("Pragma", "no-cache").json(body);
};
/**
 * Resolve the scope this authorization will carry, filtered by what the client
 * may have.
 *
 * The shape follows `clientCredentials.mts`'s deny-by-absence rule (#396): an
 * omitted `scope` draws on the client's declared `defaultScopes`, never on the
 * whole allowlist, because "forgot to send scope" must not be the maximum
 * grant.
 */
const resolveScope = (raw, client) => {
    const allowed = client.allowedScopes ?? [];
    if (raw === undefined || (typeof raw === "string" && raw.trim() === "")) {
        if (client.defaultScopes !== undefined) {
            return {
                ok: true,
                scope: client.defaultScopes.filter((s) => allowed.includes(s)),
            };
        }
        if (allowed.length === 0)
            return { ok: true, scope: [] };
        return {
            ok: false,
            error: "invalid_scope",
            description: "scope is required: this client declares no defaultScopes",
        };
    }
    // RFC 6749 §3.3: a single space-delimited string. Express turns repeated
    // `scope=` form keys into an array; defaulting that to the client's whole
    // allowlist would grant more than was asked for.
    if (typeof raw !== "string") {
        return {
            ok: false,
            error: "invalid_request",
            description: "scope must be a space-delimited string",
        };
    }
    const requested = raw.split(" ").filter((s) => s.length > 0);
    const refused = requested.filter((s) => !allowed.includes(s));
    if (refused.length > 0) {
        return {
            ok: false,
            error: "invalid_scope",
            description: `scope not permitted for this client: ${refused.join(" ")}`,
        };
    }
    return { ok: true, scope: requested };
};
/** How many times to re-draw when a generated code collides with a live one. */
const CODE_COLLISION_RETRIES = 5;
export const createDeviceAuthorizationHandler = (options) => {
    const now = options.now ?? Date.now;
    const { settings } = options;
    return async (req, res) => {
        const body = (req.body ?? {});
        // Set by `createClientAuthMiddleware`, which the module mounts ahead of
        // this handler. Its absence means the handler was wired without that
        // middleware — a composition error, not a request the caller can fix,
        // and answering it as an authentication failure is both true and the
        // only safe reading.
        const client = req.oauthClient;
        if (client === undefined) {
            fail(res, 401, {
                error: "invalid_client",
                error_description: "client authentication is required",
            });
            return;
        }
        // The token endpoint's rule, applied where the flow starts. Deny by
        // absence, as dispatch does for a grant that declares
        // `requiresExplicitGrantAllowlist` — otherwise the two endpoints
        // disagree about who may start what only one of them will finish.
        // RFC 6749 §5.2 `unauthorized_client`, the same code and wording the
        // token endpoint answers with.
        if (!isGrantTypeAllowed(client.allowedGrantTypes, DEVICE_CODE_GRANT_TYPE, {
            requireAllowlist: true,
        })) {
            options.logger?.warn({ clientId: client.clientId }, "device_authorization_grant_not_allowed");
            fail(res, 400, {
                error: "unauthorized_client",
                error_description: `client is not authorized for ${DEVICE_CODE_GRANT_TYPE}`,
            });
            return;
        }
        const scope = resolveScope(body.scope, client);
        if (!scope.ok) {
            fail(res, 400, { error: scope.error, error_description: scope.description });
            return;
        }
        const issuedAtMs = now();
        const expiresAtMs = issuedAtMs + settings.codeLifetimeSeconds * 1000;
        // A collision means two live authorizations would share a code. The
        // store refuses it rather than overwriting, and the honest response to
        // that is to draw again — not to hand the caller an error for a
        // condition it did not cause and cannot fix.
        let created = null;
        let lastError = null;
        for (let attempt = 0; attempt < CODE_COLLISION_RETRIES; attempt++) {
            const deviceCode = generateDeviceCode();
            const displayCode = generateUserCode();
            const userCode = normaliseUserCode(displayCode);
            /* c8 ignore next 3 -- generateUserCode always produces a normalisable
               code; the guard exists so a future generator change cannot store an
               un-normalised code that no typed input will ever match. */
            if (userCode === null) {
                throw new Error("generated user code failed its own normalisation");
            }
            try {
                await options.store.create({
                    deviceCode,
                    userCode,
                    clientId: client.clientId,
                    ...(scope.scope.length > 0 ? { requestedScope: scope.scope } : {}),
                    expiresAtMs,
                    intervalSeconds: settings.pollingIntervalSeconds,
                });
                created = { deviceCode, userCode: displayCode };
                break;
            }
            catch (err) {
                lastError = err;
            }
        }
        if (created === null) {
            options.logger?.warn({ clientId: client.clientId, err: String(lastError) }, "device_authorization_code_collision");
            fail(res, 500, {
                error: "server_error",
                error_description: "could not allocate a device authorization code",
            });
            return;
        }
        const response = {
            device_code: created.deviceCode,
            user_code: created.userCode,
            verification_uri: settings.verificationUri,
            expires_in: settings.codeLifetimeSeconds,
            interval: settings.pollingIntervalSeconds,
        };
        if (settings.verificationUriComplete) {
            // §3.3.1's non-textual form. The code goes in a query parameter
            // because that is what the RFC's own example does; the display form
            // is used so a human reading the QR target sees the code they would
            // otherwise have typed.
            const url = new URL(settings.verificationUri);
            url.searchParams.set("user_code", created.userCode);
            response.verification_uri_complete = url.toString();
        }
        res.status(200).set("Cache-Control", "no-store").set("Pragma", "no-cache").json(response);
    };
};
