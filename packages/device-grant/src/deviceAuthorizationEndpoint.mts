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
 * `POST /oauth/device_authorization` — RFC 8628 §3.1–§3.2 (#298).
 *
 * The device asks for a pair of codes: one it keeps and polls with, one it
 * shows the human. Nothing is authorized yet; this endpoint only opens the
 * session that the verification endpoint later decides.
 *
 * ### Why the scope is settled here and not at approval
 *
 * The request names a scope, and the approval happens minutes later on a
 * different device. Filtering against the client's `allowedScopes` at approval
 * time would mean the human is shown a scope that has not been checked yet —
 * so they could approve something the client is not permitted to have and see
 * a narrower grant appear, or approve nothing visible and get a token anyway.
 * Settling it here means what the verification page displays is exactly what
 * approving it grants.
 *
 * ### Client authentication
 *
 * RFC 8628 §3.1: "The client authentication requirements of Section 3.2.1 of
 * [RFC6749] apply to requests on this endpoint" — and §5.6 observes that
 * device clients "should be treated as public clients".
 *
 * Both are satisfied by mounting `createClientAuthMiddleware` from
 * `@o3co/auth-provider-oauth` with `allowPublicClients: true` — the same
 * middleware, with the same options, that `/oauth/token` uses. That is why
 * this handler reads `req.oauthClient` and never looks a client up itself:
 * the middleware has already enforced the registration's own
 * `tokenEndpointAuthMethod`, so a **confidential** client cannot be
 * identified by its `client_id` alone, while a public one can.
 *
 * Re-deriving that here would be a second notion of client authentication
 * living beside the canonical one, differing in exactly the ways nobody
 * notices until one of them is wrong — the drift #292 removed when it moved
 * the trusted-proxy vocabulary into a single shared matcher.
 */

import type { AuthenticatedClient } from "@o3co/auth-provider-core";
import { generateDeviceCode, generateUserCode, normaliseUserCode } from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import type { DeviceGrantDependencies } from "./types.mjs";

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
 * may have.
 *
 * The shape follows `clientCredentials.mts`'s deny-by-absence rule (#396): an
 * omitted `scope` draws on the client's declared `defaultScopes`, never on the
 * whole allowlist, because "forgot to send scope" must not be the maximum
 * grant.
 */
const resolveScope = (
	raw: unknown,
	client: AuthenticatedClient,
):
	| { readonly ok: true; readonly scope: readonly string[] }
	| { readonly ok: false; readonly error: string; readonly description: string } => {
	const allowed = client.allowedScopes ?? [];

	if (raw === undefined || (typeof raw === "string" && raw.trim() === "")) {
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

export interface DeviceAuthorizationEndpointOptions extends DeviceGrantDependencies {}

/** How many times to re-draw when a generated code collides with a live one. */
const CODE_COLLISION_RETRIES = 5;

export const createDeviceAuthorizationHandler = (
	options: DeviceAuthorizationEndpointOptions,
): RequestHandler => {
	const now = options.now ?? Date.now;
	const { settings } = options;

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
					...(scope.scope.length > 0 ? { requestedScope: scope.scope } : {}),
					expiresAtMs,
					intervalSeconds: settings.pollingIntervalSeconds,
				});
				created = { deviceCode, userCode: displayCode };
				break;
			} catch (err) {
				lastError = err;
			}
		}

		if (created === null) {
			options.logger?.warn(
				{ clientId: client.clientId, err: String(lastError) },
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
