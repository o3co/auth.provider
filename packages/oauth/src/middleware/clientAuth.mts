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

import {
	type ClientRepository,
	consoleLogger,
	type Logger,
	type PublicClient,
} from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";

// Module augmentation: expose `req.oauthClient` for consumers who compose this
// middleware onto their own routes and need the authenticated client downstream.
// Uses the global Express namespace (declared in @types/express-serve-static-core)
// which is the stable, pnpm-friendly augmentation target for both Express v4 and v5.
declare global {
	namespace Express {
		interface Request {
			/**
			 * The authenticated OAuth client, set by {@link createClientAuthMiddleware}
			 * after successful RFC 6749 §2.3.1 client authentication. Absent when the
			 * request has not been through client-auth middleware.
			 */
			oauthClient?: PublicClient;
		}
	}
}

const WWW_AUTH = 'Basic realm="oauth"';

/**
 * Decodes an `application/x-www-form-urlencoded`-encoded string per RFC 6749 §2.3.1.
 * `+` is a synonym for space in x-www-form-urlencoded encoding (distinct from %20).
 * `decodeURIComponent` alone does NOT handle `+`, so we normalise it first.
 */
function formUrlDecode(s: string): string {
	return decodeURIComponent(s.replace(/\+/g, " "));
}

/**
 * Creates RFC 6749 §2.3.1 client-authentication middleware for the /oauth/introspect
 * endpoint (and any other route requiring authenticated OAuth client access).
 *
 * Extracts client credentials from the request using:
 * 1. HTTP Basic authentication (preferred per RFC 6749 §2.3.1)
 * 2. Form-encoded `client_id` / `client_secret` body parameters (fallback)
 *
 * On success: sets `req.oauthClient` to the authenticated {@link PublicClient} and
 * calls `next()`. The built-in /introspect handler does not consume this field — it
 * is exposed for consumers who compose this middleware onto their own routes and need
 * the authenticated client's identity downstream.
 *
 * On failure: responds with 401 + `WWW-Authenticate: Basic realm="oauth"` header
 * and `{ error: "invalid_client" }` body (RFC 6749 §5.2). A differentiated
 * `error_description` is included on most failure paths to aid client debugging;
 * the repository-throw path intentionally omits it to avoid leaking server-side
 * operational detail to callers.
 *
 * @param clientRepository - used to look up the client by credential pair.
 * @param logger - structured logger for repository-failure traces. Defaults to
 *                 `consoleLogger` so existing callers compile unchanged.
 * @returns an express RequestHandler.
 */
export function createClientAuthMiddleware(
	clientRepository: ClientRepository,
	logger: Logger = consoleLogger,
): RequestHandler {
	return async (req, res, next) => {
		let clientId: string | undefined;
		let clientSecret: string | undefined;
		let malformedBasic = false;

		// RFC 6749 §2.3.1: HTTP Basic is the preferred method.
		const authHeader = req.headers.authorization;
		if (typeof authHeader === "string" && /^basic\s+/i.test(authHeader)) {
			try {
				const decoded = Buffer.from(authHeader.replace(/^basic\s+/i, ""), "base64").toString(
					"utf8",
				);
				const idx = decoded.indexOf(":");
				if (idx > 0) {
					clientId = formUrlDecode(decoded.slice(0, idx));
					clientSecret = formUrlDecode(decoded.slice(idx + 1));
				} else {
					// No colon found — malformed credential pair
					malformedBasic = true;
				}
			} catch {
				// decodeURIComponent threw — malformed percent-encoding
				malformedBasic = true;
			}
		}

		// Form-encoded is an acceptable alternative per §2.3.1 — only use when Basic
		// was absent or malformed (prevents credential confusion attacks).
		if (clientId === undefined || clientSecret === undefined) {
			if (!malformedBasic) {
				const body = req.body as Record<string, unknown> | undefined;
				if (body && typeof body.client_id === "string" && typeof body.client_secret === "string") {
					clientId = body.client_id;
					clientSecret = body.client_secret;
				}
			}
		}

		if (malformedBasic) {
			res.set("WWW-Authenticate", WWW_AUTH);
			res
				.status(401)
				.json({ error: "invalid_client", error_description: "Malformed client credentials" });
			return;
		}

		if (!clientId || !clientSecret) {
			res.set("WWW-Authenticate", WWW_AUTH);
			res
				.status(401)
				.json({ error: "invalid_client", error_description: "Client authentication is required" });
			return;
		}

		let client: PublicClient | null;
		try {
			client = await clientRepository.authenticate(clientId, clientSecret);
		} catch (err) {
			// Fail-closed: repository unavailability must not grant access.
			// Log server-side for operators; do NOT leak store details to callers.
			logger.warn({ err }, "client credential lookup failed");
			res.set("WWW-Authenticate", WWW_AUTH);
			res.status(401).json({ error: "invalid_client" });
			return;
		}

		if (!client) {
			res.set("WWW-Authenticate", WWW_AUTH);
			res
				.status(401)
				.json({ error: "invalid_client", error_description: "Invalid client credentials" });
			return;
		}

		req.oauthClient = client;
		next();
	};
}
