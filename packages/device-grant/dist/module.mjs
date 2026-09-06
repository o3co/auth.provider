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
/**
 * Module manifest for the RFC 8628 device authorization grant (#298).
 *
 * Contributes three things and requires two:
 *
 *   - the `urn:ietf:params:oauth:grant-type:device_code` grant on `/token`;
 *   - `POST /oauth/device_authorization`, where a device starts;
 *   - `POST /oauth/device/verification`, where a human answers;
 *   - `device_authorization_endpoint` in the discovery document, because a
 *     client has no other way to find the first of those (RFC 8628 §4).
 *
 * ### Secure-default opt-in
 *
 * `oauth.deviceAuthorization.enabled = false` in `reference.conf`. Mounting a
 * package must not turn on a grant; the operator says so.
 *
 * ### Two settings with no defaults
 *
 * `verification-uri` has none because there is nothing to guess — the page
 * belongs to the deployment, and a device that displays a wrong URL sends
 * users somewhere that cannot help them. A `rateLimiter` is *required* rather
 * than optional for a different reason: RFC 8628 §5.1 computes the user
 * code's entropy budget *against* a rate limit, so an unlimited deployment is
 * not a slower version of a limited one, it is 34.5 bits against an unbounded
 * attacker. Both fail at boot rather than at the first request.
 *
 * ### The verification endpoint is a CSRF target, and is guarded as one
 *
 * `POST /oauth/device/verification` authorises on the end-user session cookie
 * — the one credential a browser attaches to a request some other site made.
 * That is the whole of RFC 8628 §5.4's remote-phishing attack: any public
 * `client_id` obtains a `user_code`, a page on the attacker's origin
 * auto-submits `action=approve&user_code=…` from the victim's browser, and
 * the attacker's device collects the victim's token. Turning
 * `verification_uri_complete` off keeps the *user* typing the code; a forged
 * POST types it for them.
 *
 * So the route the module mounts is JSON-only — a form body is a "simple"
 * request the browser sends without a preflight, `application/json` is not —
 * and sits behind the same `createCsrfGuard` `/session/login` runs (#272):
 * a foreign `Origin` / `Referer` is refused outright, the server's own origin
 * or one on `session.csrf.trustedOrigins` is accepted, and a request with no
 * origin signal must carry the session's signed double-submit token. That is
 * one CSRF policy for the product rather than a second one that can drift,
 * which is why this package depends on `@o3co/auth-provider-session` rather
 * than restating an origin check. The guard is built from the `session.*`
 * config slice, so enabling the grant without one fails at boot.
 */
import { AUDIT_SINK_ABSENCE_POLICY, createRateLimitGuard, DEVICE_CODE_STORE_ABSENCE_POLICY, defineModule, } from "@o3co/auth-provider-core";
import { createClientAuthMiddleware } from "@o3co/auth-provider-oauth";
import { createCsrfGuard, createCsrfProtectionFromConfig, } from "@o3co/auth-provider-session";
import express from "express";
import { z } from "zod";
import { createDeviceAuthorizationHandler } from "./deviceAuthorizationEndpoint.mjs";
import { createDeviceCodeGrant } from "./grant.mjs";
import { DEVICE_AUTHORIZATION_RATE_LIMIT_PREFIX, DEVICE_CODE_GRANT_TYPE } from "./types.mjs";
import { createDeviceVerificationHandler } from "./verificationEndpoint.mjs";
/**
 * `oauth.deviceAuthorization.rateLimit` — the budget RFC 8628 §5.1 sizes the
 * user code against. `.int().positive()` is load-bearing: `0` is what an
 * empty environment variable coerces to, and a zero-attempt budget locks
 * every user out while a zero window is not a window. Core's
 * `resolveDeviceVerificationLimitSpec` screens the same bounds structurally
 * for configs that never passed this schema.
 */
const rateLimitSpecSchema = z.object({
    limit: z.number().int().positive(),
    windowSeconds: z.number().int().positive(),
});
/** §5.1's worked example: "only allow 5 attempts"; five minutes is half the default code lifetime. */
const DEFAULT_VERIFICATION_RATE_LIMIT = { limit: 5, windowSeconds: 300 };
export const deviceGrantConfigSchema = z.object({
    oauth: z.object({
        deviceAuthorization: z
            .object({
            /** When false (the default), this module contributes nothing. */
            enabled: z.boolean().default(false),
            /**
             * The page where the end user types the code. No default: the
             * page belongs to the deployment, and a guessed URL is one the
             * device would display to users who cannot use it.
             */
            "verification-uri": z.string().url().optional(),
            /**
             * Emit `verification_uri_complete` (RFC 8628 §3.3.1). Off by
             * default — §5.4 warns that removing the typing step removes the
             * proof that the device is in the user's possession, which is what
             * makes remote phishing hard.
             */
            "verification-uri-complete": z.boolean().default(false),
            /**
             * §5.4: "long enough lifetime to be useable ... but sufficiently
             * short to limit the usability of a code obtained for phishing".
             */
            "code-lifetime-seconds": z.number().int().min(30).max(3600).default(600),
            /** Advertised as `interval`; also what the store enforces. */
            "polling-interval-seconds": z.number().int().min(1).max(60).default(5),
            /**
             * The verification endpoint's budget per authenticated subject,
             * seeded into whichever rate-limiter adapter is wired under the
             * `device_verification` prefix (an operator-declared
             * `limits.device_verification` on the adapter still wins). This
             * is the number the "requires a rateLimiter" boot refusal
             * reasons from, so it has to be the number the limiter applies.
             */
            rateLimit: rateLimitSpecSchema.default(DEFAULT_VERIFICATION_RATE_LIMIT),
            /**
             * Declared absence for the `deviceCodeStore` slot (#363).
             * `"unsupported"` is the only value; anything else is a typo that
             * would otherwise read as a declaration.
             */
            store: z.literal("unsupported").optional(),
        })
            .default(() => ({
            enabled: false,
            "verification-uri-complete": false,
            "code-lifetime-seconds": 600,
            "polling-interval-seconds": 5,
            rateLimit: DEFAULT_VERIFICATION_RATE_LIMIT,
        })),
    }),
});
const readSettings = (deps) => {
    const slice = deps.config?.oauth?.deviceAuthorization;
    if (slice?.enabled !== true)
        return null;
    return slice;
};
const requireVerificationUri = (slice) => {
    const uri = slice["verification-uri"];
    if (typeof uri !== "string" || uri === "") {
        throw new Error("deviceGrantModule: oauth.deviceAuthorization.enabled = true requires " +
            "oauth.deviceAuthorization.verification-uri. It is the page this " +
            "deployment serves for entering the code, and the device displays it " +
            "verbatim — there is nothing sensible to default it to.");
    }
    return uri;
};
/**
 * What a disabled deployment mounts instead of the real endpoint.
 *
 * The `routes` contribution kind has no "skip me" return — a factory produces
 * a route or throws — so a config-disabled module cannot simply omit one. A
 * router that answers 404 is the honest equivalent: from a client's side it
 * is indistinguishable from the package not being installed, which is exactly
 * what `enabled = false` means. Nothing here reads the rest of the config, so
 * a deployment that leaves the grant off never trips its required settings.
 */
const disabledRoute = (id, mountPath) => {
    const router = express.Router();
    router.all("/", (_req, res) => {
        // Same cache directives as the live endpoints. A 404 with no
        // directives is exactly the shape an intermediary heuristically
        // caches — and a cached "this deployment has no device grant" would
        // outlive the operator turning it on.
        res
            .status(404)
            .set("Cache-Control", "no-store")
            .set("Pragma", "no-cache")
            .json({
            error: "not_found",
            error_description: "the device authorization grant is not enabled on this deployment " +
                "(oauth.deviceAuthorization.enabled = false)",
        });
    });
    return { id, mountPath, handler: router };
};
/**
 * The `session.*` slice the verification route's CSRF guard is built from.
 *
 * Checked structurally rather than declared in `configSchema`: the slice is
 * the session module's to validate, and every deployment that can reach this
 * endpoint mounts that module — `req.session.isAuthenticated` is its field.
 * What is refused here is the composition that enables the grant with no
 * session at all, where the guard would have no signing key and no cookie
 * name and the endpoint would be mounted with no CSRF defence.
 */
const SAME_SITE_VALUES = new Set(["lax", "strict", "none"]);
const requireSessionSlice = (deps) => {
    const session = deps.config?.session;
    // Every field `createCsrfProtectionFromConfig` reads is checked here, not
    // just the secret: a slice with no `name` would mint a cookie called
    // `undefined.csrf`, and one with no `secure`/`sameSite` would set cookie
    // attributes the operator never chose. Refuse the whole slice instead.
    const missing = [];
    if (typeof session?.secret !== "string" || session.secret === "")
        missing.push("session.secret");
    if (typeof session?.name !== "string" || session.name === "")
        missing.push("session.name");
    if (typeof session?.secure !== "boolean")
        missing.push("session.secure");
    if (!SAME_SITE_VALUES.has(session?.sameSite))
        missing.push("session.sameSite");
    if (missing.length > 0) {
        throw new Error("deviceGrantModule: oauth.deviceAuthorization.enabled = true requires the " +
            `\`session\` config slice; missing or invalid: ${missing.join(", ")}. ` +
            "POST /oauth/device/verification runs inside the end-user session and is " +
            "guarded by the same CSRF policy as /session/login — a signed double-submit " +
            "token derived from session.secret, a cookie named from session.name with " +
            "session.secure / session.sameSite, and an Origin/Referer check against " +
            "session.csrf.trustedOrigins — so without the slice the guard cannot be built " +
            "and the endpoint cannot be mounted safely.");
    }
    return session;
};
/**
 * OR-5: the outage policy for a limiter-backend failure is `rateLimit.failMode`
 * — one decision for the product, read by every guarded route. Defaulting it
 * here would be a second policy, so its absence is a boot refusal.
 */
const requireFailMode = (deps) => {
    const failMode = deps.config?.rateLimit?.failMode;
    if (failMode !== "open" && failMode !== "closed") {
        throw new Error("deviceGrantModule: oauth.deviceAuthorization.enabled = true requires " +
            'rateLimit.failMode ("open" | "closed"). POST /oauth/device_authorization ' +
            "runs behind the shared rate-limit guard, and what the guard does when the " +
            "limiter backend is down is the product's outage policy, not this module's.");
    }
    return failMode;
};
const requireRateLimiter = (deps) => {
    if (deps.rateLimiter === undefined) {
        throw new Error("deviceGrantModule: oauth.deviceAuthorization.enabled = true requires a " +
            "rateLimiter component. RFC 8628 §5.1 sizes the user code's entropy " +
            "against a rate limit — 8 base-20 characters is ~34.5 bits, which is " +
            "sufficient only because an attacker gets a handful of attempts. " +
            "Without a limiter that argument does not hold, so this refuses to " +
            "boot rather than serving a code that looks strong and is not.");
    }
    return deps.rateLimiter;
};
export const deviceGrantModule = defineModule({
    name: "device-grant",
    configSchema: deviceGrantConfigSchema,
    requires: ["config", "clientRepository", "keyStore"],
    optional: ["deviceCodeStore", "rateLimiter", "logger", "auditSink"],
    // #363: optional to wire, not optional to decide. A composition with no
    // sink discards every device approval — a consent event — with no
    // symptom, so it has to write `audit.sink.type = "none"` to say so.
    absencePolicies: {
        deviceCodeStore: DEVICE_CODE_STORE_ABSENCE_POLICY,
        auditSink: AUDIT_SINK_ABSENCE_POLICY,
    },
    contributes: {
        grants: {
            [DEVICE_CODE_GRANT_TYPE]: (deps) => {
                const slice = readSettings(deps);
                if (slice === null) {
                    // Disabled: contribute a handler that refuses, rather than
                    // omitting the key. `unsupported_grant_type` is what the token
                    // endpoint answers for an unregistered grant anyway, so the
                    // observable behaviour matches "not installed".
                    return {
                        async handle() {
                            return {
                                result: {
                                    status: 400,
                                    error: "unsupported_grant_type",
                                    errorDescription: "the device authorization grant is not enabled",
                                },
                            };
                        },
                    };
                }
                return createDeviceCodeGrant({
                    store: deps.deviceCodeStore,
                    keyStore: deps.keyStore,
                    accessTokenExpiresIn: deps.config.oauth.accessToken.expiresIn,
                    logger: deps.logger,
                });
            },
        },
        routes: [
            (deps) => {
                const slice = readSettings(deps);
                if (slice === null) {
                    return disabledRoute("device-authorization", "/oauth/device_authorization");
                }
                const router = express.Router();
                // Router-level body parsing, matching `oauthModule` and the
                // WebAuthn routes: `createApp` installs no global parser.
                router.use(express.json({ limit: "16kb" }));
                router.use(express.urlencoded({ extended: false, limit: "16kb" }));
                // Throttled like every other public entry point (#325), and
                // AHEAD of client authentication — the token endpoint's D-6
                // ordering — so repeated unauthenticated hits are bounded before
                // they reach a repository lookup, and so a public client cannot
                // fill the device-code store by asking. Keyed
                // `device_authorization:ip:<ip>`; the adapter resolves the spec
                // by that prefix and falls back to its default.
                router.use(createRateLimitGuard({
                    limiter: requireRateLimiter(deps),
                    tag: DEVICE_AUTHORIZATION_RATE_LIMIT_PREFIX,
                    failMode: requireFailMode(deps),
                    ...(deps.logger ? { logger: deps.logger } : {}),
                    auditSink: deps.auditSink,
                }));
                // RFC 8628 §3.1 applies RFC 6749 §3.2.1's client-authentication
                // requirements to this endpoint, and §5.6 expects device clients
                // to be public. `allowPublicClients: true` is exactly that pair:
                // a public client is identified by `client_id`, a confidential
                // one must still present its secret. The same middleware and the
                // same option `/oauth/token` uses, so there is one notion of
                // client authentication rather than two that can drift.
                router.use(createClientAuthMiddleware(deps.clientRepository, {
                    issuer: deps.config.oauth.jwt.issuer,
                    allowPublicClients: true,
                    ...(deps.logger ? { logger: deps.logger } : {}),
                }));
                router.post("/", createDeviceAuthorizationHandler({
                    store: deps.deviceCodeStore,
                    settings: {
                        verificationUri: requireVerificationUri(slice),
                        verificationUriComplete: slice["verification-uri-complete"],
                        codeLifetimeSeconds: slice["code-lifetime-seconds"],
                        pollingIntervalSeconds: slice["polling-interval-seconds"],
                    },
                    logger: deps.logger,
                }));
                return {
                    id: "device-authorization",
                    mountPath: "/oauth/device_authorization",
                    handler: router,
                };
            },
            (deps) => {
                const slice = readSettings(deps);
                if (slice === null) {
                    return disabledRoute("device-verification", "/oauth/device/verification");
                }
                const router = express.Router();
                // JSON only, deliberately — see the file header. A form body is
                // a "simple" request a browser sends cross-site with the
                // victim's cookie and no preflight; JSON is not. With no form
                // parser mounted, a forged form POST carries no `action` even
                // if it reached the handler.
                router.use(express.json({ limit: "16kb" }));
                // The session guard, verbatim: foreign origin refused, same
                // origin or `session.csrf.trustedOrigins` accepted, no origin
                // signal → the signed double-submit token `GET /session/csrf`
                // mints. On the whole route rather than on `approve` / `deny`
                // alone, for the reason the three actions are one route: no
                // way to add a fourth that forgets it.
                const sessionSlice = requireSessionSlice(deps);
                router.post("/", createCsrfGuard({
                    csrf: createCsrfProtectionFromConfig(sessionSlice),
                    trustedOrigins: sessionSlice.csrf?.trustedOrigins ?? [],
                    ...(deps.logger ? { logger: deps.logger } : {}),
                }), createDeviceVerificationHandler({
                    store: deps.deviceCodeStore,
                    rateLimiter: requireRateLimiter(deps),
                    settings: {
                        verificationUri: requireVerificationUri(slice),
                        verificationUriComplete: slice["verification-uri-complete"],
                        codeLifetimeSeconds: slice["code-lifetime-seconds"],
                        pollingIntervalSeconds: slice["polling-interval-seconds"],
                    },
                    logger: deps.logger,
                    auditSink: deps.auditSink,
                }));
                return {
                    id: "device-verification",
                    mountPath: "/oauth/device/verification",
                    handler: router,
                };
            },
        ],
        discoveryMetadata: [
            (deps) => {
                const slice = readSettings(deps);
                if (slice === null)
                    return {};
                // RFC 8628 §4. A client that cannot discover this endpoint cannot
                // start the flow, so the metadata is the feature being reachable
                // rather than a description of it.
                const issuer = deps.config.oauth.jwt.issuer;
                return {
                    metadata: {
                        device_authorization_endpoint: new URL("/oauth/device_authorization", issuer).toString(),
                    },
                    // The grant appears in `grant_types_supported` through the same
                    // aggregation every other grant uses (#283).
                    grantTypes: [DEVICE_CODE_GRANT_TYPE],
                };
            },
        ],
    },
});
