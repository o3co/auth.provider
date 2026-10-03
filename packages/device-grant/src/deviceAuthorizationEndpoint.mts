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
 * `POST /oauth/device_authorization` — RFC 8628 §3.1–§3.2. Opens a pending
 * device authorization (a polling `device_code` and a displayed `user_code`);
 * the verification endpoint decides it later.
 *
 * The scope is checked against the client's `allowedScopes` here, not at
 * approval, so what the verification page shows is exactly what approving it
 * grants.
 *
 * Client authentication (RFC 8628 §3.1, §5.6) belongs to
 * `createClientAuthMiddleware` from `@o3co/auth-provider-oauth`, mounted ahead
 * with `allowPublicClients: true` exactly as for `/oauth/token`. This handler
 * reads `req.oauthClient` and never looks a client up itself: a second notion
 * of client authentication would drift from the canonical one.
 *
 * The client must be allowed the `device_code` grant under the token
 * endpoint's rule (`isGrantTypeAllowed`, explicit allowlist required).
 * Otherwise any client could mint real user codes and verification prompts —
 * phishing material — for a grant that can never complete.
 */

import type { AuthenticatedClient } from "@o3co/auth-provider-core";
import {
	DeviceCodeStoreError,
	generateDeviceCode,
	generateUserCode,
	isGrantTypeAllowed,
	loggableError,
	normaliseUserCode,
	readSpaceDelimitedParameter,
	sanitizeErrorText,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import { DEVICE_CODE_STORE_UNAVAILABLE, reportDeviceCodeStoreOutage } from "./storeOutage.mjs";
import { DEVICE_CODE_GRANT_TYPE, type DeviceGrantDependencies } from "./types.mjs";

interface OAuthErrorBody {
	readonly error: string;
	readonly error_description?: string;
}

const fail = (res: Response, status: number, body: OAuthErrorBody): void => {
	// RFC 6749 §5.2 cache directives: an error naming a client_id must not be
	// held by an intermediary and replayed to someone else.
	res.status(status).set("Cache-Control", "no-store").set("Pragma", "no-cache").json(body);
};

/**
 * Resolve the scope this authorization will carry, filtered by what the client
 * may have. An omitted `scope` draws on `defaultScopes`, never on the whole
 * allowlist: "forgot to send scope" must not be the maximum grant.
 */
const resolveScope = (
	raw: unknown,
	client: AuthenticatedClient,
):
	| { readonly ok: true; readonly scope: readonly string[] }
	| { readonly ok: false; readonly error: string; readonly description: string } => {
	const allowed = client.allowedScopes ?? [];

	// RFC 6749 §3.3: a single space-delimited string. Express turns repeated
	// `scope=` form keys into an array; defaulting that to the client's whole
	// allowlist would grant more than was asked for. RFC 6749 §3.2: a
	// parameter sent without a value is treated as omitted — `scope=""` in a
	// form body, `"scope": null` in a JSON one.
	if (raw !== undefined && raw !== null && typeof raw !== "string") {
		return {
			ok: false,
			error: "invalid_request",
			description: "scope must be a space-delimited string",
		};
	}
	// Read strictly, as every token-endpoint grant reads a request: the space
	// is the one delimiter, and an entry that is not a scope-token makes the
	// value malformed. Spaces alone name nothing, which is an omitted scope.
	const requested = typeof raw === "string" ? readSpaceDelimitedParameter(raw) : [];
	if (requested === null) {
		return {
			ok: false,
			error: "invalid_scope",
			description: "scope is not a space-delimited list of scope-tokens",
		};
	}

	if (requested.length === 0) {
		if (client.defaultScopes !== undefined) {
			return {
				ok: true,
				scope: client.defaultScopes.filter((s: string) => allowed.includes(s)),
			};
		}
		if (allowed.length === 0) return { ok: true, scope: [] };
		return {
			ok: false,
			error: "invalid_scope",
			description: "scope is required: this client declares no defaultScopes",
		};
	}

	const refused = requested.filter((s) => !allowed.includes(s));
	if (refused.length > 0) {
		return {
			ok: false,
			error: "invalid_scope",
			// The refused values are the client's own: RFC 6749 Appendix A.8 holds
			// the description to 1*NQSCHAR, so any other character goes out as `?`.
			description: sanitizeErrorText(`scope not permitted for this client: ${refused.join(" ")}`),
		};
	}
	return { ok: true, scope: requested };
};

export interface DeviceAuthorizationEndpointOptions extends DeviceGrantDependencies {}

/** How many times to re-draw when a generated code collides with a live one. */
const CODE_COLLISION_RETRIES = 5;

/**
 * The bounds on the two device-code settings, in whole seconds: what
 * `deviceGrantConfigSchema` holds `device-grant.*` to, and
 * what this handler holds settings handed over as numbers to. RFC 8628 §5.4
 * wants a code "long enough … to be useable" and "sufficiently short to limit
 * the usability of a code obtained for phishing"; the interval is advertised
 * and enforced by the store.
 */
export const DEVICE_CODE_LIFETIME_SECONDS = { min: 30, max: 3600 } as const;
export const DEVICE_POLLING_INTERVAL_SECONDS = { min: 1, max: 60 } as const;

const requireWholeSeconds = (
	name: string,
	value: number,
	bounds: { readonly min: number; readonly max: number },
): void => {
	if (!(Number.isInteger(value) && value >= bounds.min && value <= bounds.max)) {
		throw new RangeError(
			`createDeviceAuthorizationHandler: ${name} must be a whole number of seconds from ${bounds.min} to ${bounds.max} (got ${String(value)})`,
		);
	}
};

export const createDeviceAuthorizationHandler = (
	options: DeviceAuthorizationEndpointOptions,
): RequestHandler => {
	const now = options.now ?? Date.now;
	const { settings } = options;
	// Validated once at build time, so a bad value fails the composition
	// rather than every request.
	requireWholeSeconds(
		"settings.codeLifetimeSeconds",
		settings.codeLifetimeSeconds,
		DEVICE_CODE_LIFETIME_SECONDS,
	);
	requireWholeSeconds(
		"settings.pollingIntervalSeconds",
		settings.pollingIntervalSeconds,
		DEVICE_POLLING_INTERVAL_SECONDS,
	);

	return async (req: Request, res: Response): Promise<void> => {
		const body = (req.body ?? {}) as Record<string, unknown>;

		// Set by `createClientAuthMiddleware`, which the module mounts ahead of
		// this handler. Its absence means the handler was wired without that
		// middleware — a composition error, not a request the caller can fix,
		// and answering it as an authentication failure is both true and the
		// only safe reading.
		const client = (req as { oauthClient?: AuthenticatedClient }).oauthClient;
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
		if (
			!isGrantTypeAllowed(client.allowedGrantTypes, DEVICE_CODE_GRANT_TYPE, {
				requireAllowlist: true,
			})
		) {
			options.logger?.warn({ clientId: client.clientId }, "device_authorization_grant_not_allowed");
			fail(res, 400, {
				error: "unauthorized_client",
				error_description: `client is not authorized for grant_type '${DEVICE_CODE_GRANT_TYPE}'`,
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

		// Store refusals: `collision` (a live record holds the code) is retried
		// with fresh codes; `full` (at cap, every record live) is RFC 6749 §5.2
		// `temporarily_unavailable`, since re-drawing cannot free a slot; any
		// other error is a store outage, answered 503 at once.
		let created: { deviceCode: string; userCode: string } | null = null;
		let lastError: unknown = null;
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
					requestedScope: scope.scope.length > 0 ? scope.scope : undefined,
					expiresAtMs,
					intervalSeconds: settings.pollingIntervalSeconds,
				});
				created = { deviceCode, userCode: displayCode };
				break;
			} catch (err) {
				if (err instanceof DeviceCodeStoreError && err.reason === "full") {
					options.logger?.warn({ clientId: client.clientId }, "device_authorization_store_full");
					fail(res, 503, {
						error: "temporarily_unavailable",
						error_description: "no capacity for a new device authorization; retry later",
					});
					return;
				}
				if (!(err instanceof DeviceCodeStoreError && err.reason === "collision")) {
					reportDeviceCodeStoreOutage(
						options.logger,
						"device_authorization_store_unavailable",
						err,
						{ clientId: client.clientId },
					);
					fail(res, 503, {
						error: DEVICE_CODE_STORE_UNAVAILABLE.error,
						error_description: DEVICE_CODE_STORE_UNAVAILABLE.description,
					});
					return;
				}
				lastError = err;
			}
		}

		if (created === null) {
			options.logger?.warn(
				{ clientId: client.clientId, err: loggableError(lastError) },
				"device_authorization_code_collision",
			);
			fail(res, 500, {
				error: "server_error",
				error_description: "could not allocate a device authorization code",
			});
			return;
		}

		const response: Record<string, unknown> = {
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
