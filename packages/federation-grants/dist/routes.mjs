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
 * The router both routes live in, and the order its middleware runs in
 * (#593, D9).
 *
 *   1. cache directives and correlation, ahead of anything that can answer;
 *   2. the throttle, keyed on the IP, BEFORE client authentication, so that
 *      repeated unauthenticated hits are bounded before they reach a
 *      repository lookup;
 *   3. content type and body parsing;
 *   4. client authentication;
 *   5. the handlers;
 *   6. everything this package does not serve, as a 404;
 *   7. a sanitizing error handler, for what the parsers reject.
 *
 * Authentication before domain validation, deliberately: an unauthenticated
 * caller must not be able to learn anything about a grant, including by
 * measuring how long a refusal took.
 *
 * Exported so a composition root that mounts the handlers itself gets the same
 * chain rather than a hand-assembled approximation of it — the ordering above
 * is the security property, not a convenience.
 */
import { createRateLimitGuard, } from "@o3co/auth-provider-core";
import { createClientAuthMiddleware } from "@o3co/auth-provider-oauth";
import express from "express";
import { createRouteDenialAudit } from "./denialAudit.mjs";
import { createFederationGrantCreateHandler, createFederationGrantReauthorizeHandler, } from "./lodgeRoute.mjs";
import { createSanitizedAuditSink, createSanitizedLogger } from "./report.mjs";
import { createRequestIdMiddleware } from "./requestId.mjs";
import { createFederationGrantRevokeHandler } from "./revokeRoute.mjs";
import { createFederationGrantStatusHandler } from "./statusRoute.mjs";
import { createFederationGrantTokenHandler, } from "./tokenRoute.mjs";
/** The shared prefix both routes are throttled under: `federation_grants:ip:<ip>`. */
export const FEDERATION_GRANTS_RATE_LIMIT_PREFIX = "federation_grants";
/** At most 16 KiB of body — the same bound the OAuth routes use. */
const BODY_LIMIT = "16kb";
const BODY_LIMIT_BYTES = 16 * 1024;
/**
 * The body limit, restated ahead of the parsers.
 *
 * These routes live under `/oauth`, and `oauthModule` mounts its own router
 * there whose first two middlewares are `express.json()` and
 * `express.urlencoded()` with the library's defaults. Whenever that router is
 * mounted ahead of this one, those parsers run first — and `body-parser` does
 * not parse a body twice, so the `limit` below is simply skipped and a body up
 * to the default 100 KiB arrives here. Checking `Content-Length` first is the
 * one form of this bound that holds whatever else is mounted, and in whatever
 * order.
 *
 * It does not make this package independent of mounting order: a malformed
 * body is still rejected by whichever parser reaches it first, and that
 * refusal carries neither this package's correlation nor its cache
 * directives. See the README — a composition root that wants those installs
 * `federationGrantsModules` ahead of `oauthModule`.
 */
const withinBodyLimit = (req, res, next) => {
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > BODY_LIMIT_BYTES) {
        res.status(413).json({ error: "invalid_request", error_description: "body_too_large" });
        return;
    }
    next();
};
/**
 * `Cache-Control` / `Pragma` on every exit, live or refused, ahead of anything
 * that can answer. A 404 with no directives is the shape an intermediary
 * caches heuristically, and a cached "this deployment has no federation
 * grants" would outlive the operator turning them on.
 */
export const noStore = (_req, res, next) => {
    res.set("Cache-Control", "no-store").set("Pragma", "no-cache");
    next();
};
/**
 * The last handler under the mount path: every method and sub-path this
 * package does not serve.
 *
 * The body carries no description, unlike the neighbouring packages'
 * refusals. That is what a disabled deployment needs:
 * `{"error":"not_found"}` is byte-identical to what a deployment without the
 * package installed answers, so an unauthenticated caller cannot learn that
 * offline delegation is one configuration key away. On an enabled deployment
 * it is the answer for a method that does not exist — and there is no `GET`
 * status alias to point anyone at.
 */
export const notFound = (_req, res) => {
    res.status(404).json({ error: "not_found" });
};
/** Cache directives then correlation: the two things every exit carries. */
const transport = () => {
    const router = express.Router();
    router.use(noStore);
    router.use(createRequestIdMiddleware());
    return router;
};
/** What a deployment that has not enabled the feature mounts. */
export function createDisabledFederationGrantRouter() {
    const router = express.Router();
    router.use(transport());
    router.use(notFound);
    return router;
}
/**
 * The two media types a body may arrive in.
 *
 * Checked rather than left to the parsers: with neither parser matching, the
 * body would silently be `{}` and the caller would be told `sub is required`
 * for a request whose `sub` they did send. An absent content type is not
 * refused here — a request with no body is a parse failure, which is a more
 * useful answer than an argument about headers.
 */
const supportedContentType = (req, res, next) => {
    const header = req.headers["content-type"];
    if (header === undefined)
        return next();
    const media = header.split(";")[0]?.trim().toLowerCase();
    if (media === "application/json" || media === "application/x-www-form-urlencoded") {
        return next();
    }
    res.status(415).json({
        error: "invalid_request",
        error_description: "unsupported_content_type",
    });
};
/**
 * What the body parsers reject, in this package's own vocabulary.
 *
 * Nothing of the parser's error reaches the caller: `body-parser` puts the
 * offending input into its message for a JSON syntax error, so the `type` it
 * classifies with is all that is read.
 */
export const parserErrors = (error, _req, res, next) => {
    if (res.headersSent)
        return next(error);
    const type = error.type;
    if (type === "entity.too.large") {
        res.status(413).json({ error: "invalid_request", error_description: "body_too_large" });
        return;
    }
    if (type === "entity.parse.failed" || type === "encoding.unsupported") {
        res.status(400).json({ error: "invalid_request", error_description: "malformed_body" });
        return;
    }
    // A composition or programming fault: a fixed description, because whatever
    // is in the error is not the caller's business.
    res.status(500).json({ error: "server_error", error_description: "unexpected_error" });
};
export function createFederationGrantRouter(options) {
    const router = express.Router();
    router.use(transport());
    // Before the throttle and before authentication, because what it watches
    // for is a response those two write themselves: the handler is not the only
    // thing that can refuse a token request, and until this existed it was the
    // only thing auditing one.
    for (const operation of ["token", "revoke"]) {
        router.use(`/:grantId/${operation}`, createRouteDenialAudit({
            ...(options.auditSink === undefined ? {} : { sink: options.auditSink }),
            operation,
            now: options.now ?? (() => new Date()),
            background: options.background,
        }));
    }
    if (options.acquisition !== undefined) {
        const requestDenials = createRouteDenialAudit({
            ...(options.auditSink === undefined ? {} : { sink: options.auditSink }),
            operation: "request",
            now: options.now ?? (() => new Date()),
            background: options.background,
        });
        // `all` on the exact collection path, not `use`: `use("/")` would match
        // every path under the mount and count a token refusal as a lodging one.
        router.all("/", requestDenials);
        router.use("/:grantId/reauthorize", requestDenials);
    }
    // Ahead of client authentication, as the token endpoint orders it: repeated
    // unauthenticated hits are bounded before they reach a repository lookup.
    // `deniedDescription` keeps this route's throttle speaking the same
    // vocabulary as core's — `rate_limited` with the reason `provider` — rather
    // than whichever budget name the limiter adapter reports.
    router.use(createRateLimitGuard({
        limiter: options.rateLimiter,
        tag: FEDERATION_GRANTS_RATE_LIMIT_PREFIX,
        failMode: options.failMode,
        deniedDescription: "provider",
        ...(options.logger === undefined ? {} : { logger: createSanitizedLogger(options.logger) }),
        // Its `rate_limit.unavailable` event carries the limiter's own error
        // message; the same allowlist the logger gets applies to the sink.
        ...(options.auditSink === undefined
            ? {}
            : { auditSink: createSanitizedAuditSink(options.auditSink) }),
    }));
    router.use(supportedContentType);
    router.use(withinBodyLimit);
    router.use(express.json({ limit: BODY_LIMIT }));
    router.use(express.urlencoded({ extended: false, limit: BODY_LIMIT }));
    router.use(createClientAuthMiddleware(options.clientRepository, {
        issuer: options.issuer,
        // `allowPublicClients` omitted: a public client is identified by a
        // value that is not a secret, and nothing else here proves it is the
        // client it says it is.
        ...(options.replaySeenSet === undefined ? {} : { replaySeenSet: options.replaySeenSet }),
        ...(options.logger === undefined ? {} : { logger: createSanitizedLogger(options.logger) }),
    }));
    router.post("/:grantId/token", createFederationGrantTokenHandler(options));
    router.post("/:grantId/status", createFederationGrantStatusHandler(options));
    router.post("/:grantId/revoke", createFederationGrantRevokeHandler(options));
    if (options.acquisition !== undefined) {
        const lodging = { ...options, acquisition: options.acquisition };
        router.post("/", createFederationGrantCreateHandler(lodging));
        router.post("/:grantId/reauthorize", createFederationGrantReauthorizeHandler(lodging));
    }
    router.use(notFound);
    router.use(parserErrors);
    return router;
}
