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
import { emitAuditEvent, normaliseUserCode } from "@o3co/auth-provider-core";
import { DEVICE_VERIFICATION_RATE_LIMIT_PREFIX } from "./types.mjs";
const ACTIONS = ["lookup", "approve", "deny"];
const respond = (res, status, body) => {
    res.status(status).set("Cache-Control", "no-store").json(body);
};
/**
 * The authenticated end user, from the session the deployment's verification
 * page runs inside.
 *
 * Returns `null` when there is nobody logged in. That is a 401, not a
 * redirect: this is a JSON API called by a page, and the page owns what to do
 * about a missing session.
 */
const subjectOf = (req) => {
    const session = req
        .session;
    if (session?.isAuthenticated !== true)
        return null;
    const id = session.user?.id;
    return typeof id === "string" && id !== "" ? id : null;
};
export const createDeviceVerificationHandler = (options) => {
    const now = options.now ?? Date.now;
    return async (req, res) => {
        const subject = subjectOf(req);
        if (subject === null) {
            respond(res, 401, {
                error: "login_required",
                error_description: "an authenticated end-user session is required to approve a device",
            });
            return;
        }
        const body = (req.body ?? {});
        const action = body.action;
        if (typeof action !== "string" || !ACTIONS.includes(action)) {
            respond(res, 400, {
                error: "invalid_request",
                error_description: `action must be one of: ${ACTIONS.join(", ")}`,
            });
            return;
        }
        // Counted before the code is even parsed. A malformed code is still an
        // attempt, and excluding it would hand an attacker an unmetered way to
        // probe which shapes the endpoint accepts.
        const decision = await options.rateLimiter.check(`${DEVICE_VERIFICATION_RATE_LIMIT_PREFIX}:user:${subject}`, { userId: subject, ...(req.ip === undefined ? {} : { ip: req.ip }) });
        if (!decision.allowed) {
            options.logger?.warn({ subject, action, remaining: decision.remaining }, "device_verification_rate_limited");
            emitAuditEvent(options.auditSink, {
                timestamp: new Date(),
                type: "device.rate_limited",
                subject,
                ip: req.ip,
                userAgent: req.get("user-agent"),
                details: { action, remaining: decision.remaining },
            });
            respond(res, 429, {
                error: "slow_down",
                error_description: "too many device code attempts",
            });
            return;
        }
        const rawUserCode = body.user_code;
        const userCode = typeof rawUserCode === "string" ? normaliseUserCode(rawUserCode) : null;
        if (userCode === null) {
            // Deliberately the same answer as "no such code": telling a caller
            // that a code is well-formed but unknown, distinctly from
            // malformed, narrows the search space for free.
            respond(res, 404, {
                error: "invalid_user_code",
                error_description: "that code is not valid — check it and try again",
            });
            return;
        }
        const nowMs = now();
        if (action === "lookup") {
            const authorization = await options.store.findPendingByUserCode(userCode, nowMs);
            if (authorization === null) {
                respond(res, 404, {
                    error: "invalid_user_code",
                    error_description: "that code is not valid — check it and try again",
                });
                return;
            }
            // §5.4: "it is RECOMMENDED to inform the user that they are
            // authorizing a device ... and to confirm that the device is in
            // their possession". The page needs the client's identity and the
            // scope to say that; it gets nothing else.
            respond(res, 200, {
                client_id: authorization.clientId,
                scope: (authorization.requestedScope ?? []).join(" "),
                expires_at: new Date(authorization.expiresAtMs).toISOString(),
            });
            return;
        }
        const outcome = action === "approve"
            ? // `grantedScope` is deliberately omitted: the port grants
                // `requestedScope`, which was settled and filtered against the
                // client's allowlist when the device asked. Re-reading it here
                // to pass it back would open a window between the lookup that
                // showed the user a scope and the write that grants one.
                await options.store.approve({ userCode, subject, nowMs })
            : await options.store.deny(userCode, nowMs);
        switch (outcome.status) {
            case "ok": {
                const { authorization } = outcome;
                const scope = (authorization.grantedScope ?? authorization.requestedScope ?? []).join(" ");
                options.logger?.info?.({ subject, clientId: authorization.clientId, action }, "device_authorization_decided");
                // Two literal emission sites rather than a computed type: the
                // inventory drift guard in core reads the `type:` literal at
                // each call, and a ternary would hide one name from it.
                if (action === "approve") {
                    emitAuditEvent(options.auditSink, {
                        timestamp: new Date(),
                        type: "device.approved",
                        subject,
                        clientId: authorization.clientId,
                        ip: req.ip,
                        userAgent: req.get("user-agent"),
                        details: { scope },
                    });
                }
                else {
                    emitAuditEvent(options.auditSink, {
                        timestamp: new Date(),
                        type: "device.denied",
                        subject,
                        clientId: authorization.clientId,
                        ip: req.ip,
                        userAgent: req.get("user-agent"),
                        details: { scope },
                    });
                }
                respond(res, 200, {
                    status: action === "approve" ? "approved" : "denied",
                    client_id: authorization.clientId,
                });
                return;
            }
            case "expired":
                respond(res, 410, {
                    error: "expired_token",
                    error_description: "that code has expired — start again on the device",
                });
                return;
            case "already_decided":
                // A second decision must not overwrite the first: a user who
                // denied a phishing prompt must not be able to be talked into
                // "just trying again".
                respond(res, 409, {
                    error: "already_decided",
                    error_description: `this code was already ${outcome.current}`,
                });
                return;
            default:
                respond(res, 404, {
                    error: "invalid_user_code",
                    error_description: "that code is not valid — check it and try again",
                });
        }
    };
};
