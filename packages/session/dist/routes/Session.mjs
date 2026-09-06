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
import { randomUUID } from "node:crypto";
import { extractUserClaims, } from "@o3co/auth-provider-core";
import rateLimit from "express-rate-limit";
const DEFAULT_SESSION_TTL_MS = 86400_000;
export const createRouter = (express, { userRepository, config, userSessionStore, sessionTtlMs = DEFAULT_SESSION_TTL_MS, }) => {
    const router = express.Router();
    const allowedOrigins = config.cors.allowedOrigins;
    const verifyCsrfOrigin = (req, res, next) => {
        const origin = req.get("origin");
        if (!origin) {
            next();
            return;
        }
        const serverOrigin = `${req.protocol}://${req.get("host")}`;
        if (origin !== serverOrigin && !allowedOrigins.includes(origin)) {
            res.status(403).json({ message: "forbidden" });
            return;
        }
        next();
    };
    const loginRateLimit = rateLimit({
        windowMs: config.rateLimit.login.windowMs,
        limit: config.rateLimit.login.limit,
        standardHeaders: true,
        legacyHeaders: false,
    });
    router
        .use(express.json())
        .use(express.urlencoded({ extended: false }))
        .post("/login", verifyCsrfOrigin, loginRateLimit, (req, res, next) => {
        const { redirect_to } = req.body;
        if (redirect_to != null) {
            if (typeof redirect_to !== "string" || redirect_to.length > 2048) {
                res.status(400).json({
                    error: "invalid_redirect",
                    error_description: "Invalid redirect_to",
                });
                return;
            }
            try {
                const parsed = new URL(redirect_to);
                if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
                    res.status(400).json({
                        error: "invalid_redirect",
                        error_description: "Invalid redirect URL scheme",
                    });
                    return;
                }
                const cookieDomain = config.session.domain;
                if (cookieDomain) {
                    const normalizedDomain = cookieDomain.replace(/^\./, "");
                    if (parsed.hostname !== normalizedDomain &&
                        !parsed.hostname.endsWith(`.${normalizedDomain}`)) {
                        res.status(400).json({
                            error: "invalid_redirect",
                            error_description: "Redirect domain not allowed",
                        });
                        return;
                    }
                }
            }
            catch {
                res.status(400).json({
                    error: "invalid_redirect",
                    error_description: "Invalid redirect URL",
                });
                return;
            }
        }
        next();
    }, async (req, res) => {
        const username = typeof req.body?.username === "string" ? req.body.username : undefined;
        const password = typeof req.body?.password === "string" ? req.body.password : undefined;
        if (!username || !password) {
            return res.status(400).json({
                error: "invalid_request",
                error_description: "missing credentials",
            });
        }
        let user;
        try {
            user = await userRepository.authenticate(username, password);
        }
        catch (err) {
            console.warn({ err }, "local login authenticate failed");
            return res.status(503).json({
                error: "temporarily_unavailable",
                error_description: "User directory temporarily unavailable",
            });
        }
        if (!user) {
            return res.status(401).json({
                error: "invalid_credentials",
                error_description: "Incorrect username or password.",
            });
        }
        const redirectTo = req.body.redirect_to;
        // Generate sid and create UserSession before regenerating the browser session,
        // so we can restore the sid on the new session afterwards.
        let sid;
        if (userSessionStore) {
            const claims = extractUserClaims(user);
            const now = new Date();
            sid = randomUUID();
            try {
                await userSessionStore.create({
                    sid,
                    sub: user.id,
                    authTime: now,
                    expiresAt: new Date(now.getTime() + sessionTtlMs),
                    federations: [],
                    claims,
                });
            }
            catch {
                // Fail-closed: store unavailable — return controlled 503 JSON rather
                // than an unhandled rejection hitting Express's default HTML error
                // handler. Matches the /token grant fail-closed pattern (CP-16/CP-17).
                // RFC 6749 §5.2 error shape for consistency with other /login failures.
                return res.status(503).json({
                    error: "temporarily_unavailable",
                    error_description: "Session store temporarily unavailable",
                });
            }
        }
        req.session.regenerate((err) => {
            if (err) {
                // Best-effort rollback: UserSession was created but session regeneration failed.
                // Delete the orphan record so it doesn't leak. Ignore cleanup errors — the
                // primary error is already being returned to the caller.
                if (sid && userSessionStore) {
                    userSessionStore.delete(sid).catch(() => {
                        /* best-effort cleanup */
                    });
                }
                return res.status(500).json({ message: "Error regenerating session" });
            }
            req.session.isAuthenticated = true;
            req.session.user = user;
            if (redirectTo) {
                req.session.redirectTo = redirectTo;
            }
            // Restore sid on the new session so downstream (token/introspect) can read it.
            if (sid) {
                req.session.sid = sid;
            }
            return res.status(200).json({ message: "Logged in successfully" });
        });
    })
        .post("/logout", verifyCsrfOrigin, (req, res) => {
        req.session.destroy((err) => {
            if (err) {
                return res.status(500).json({ message: "Error logging out" });
            }
            return res.status(200).json({ message: "Logged out successfully" });
        });
    });
    return router;
};
