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
 * `grant_type=urn:ietf:params:oauth:grant-type:device_code` — RFC 8628 §3.4,
 * §3.5 (#298).
 *
 * The device polls here until its user answers somewhere else. Almost all of
 * this handler is about answering *precisely enough*: RFC 8628 defines four
 * error codes for four different states, and a client library's whole control
 * flow is built on telling them apart.
 *
 *   - `authorization_pending` — keep polling, nothing has happened.
 *   - `slow_down` — keep polling, but you are going too fast. §3.5: "the
 *     interval MUST be increased by 5 seconds for this and all subsequent
 *     requests".
 *   - `access_denied` — stop; the user said no.
 *   - `expired_token` — stop; the window closed.
 *
 * Collapsing any pair of these into `invalid_grant` turns a client that would
 * have shown "you denied this on your phone" into one that retries forever.
 *
 * ### Where the interval is enforced
 *
 * In the store, not here. The check and the state change have to be one
 * operation — see `DeviceCodeStore.poll` — and a handler that read the record,
 * compared timestamps, and wrote back would let two concurrent polls both pass
 * the gate.
 *
 * ### Client binding
 *
 * The device code is issued to one client and only that client may redeem it.
 * A device code leaked to another registered client would otherwise be
 * redeemable by it, converting a leak into a full impersonation of the user's
 * approval. The check reads the authenticated client identity rather than the
 * body — the body is attacker-controlled, and reading it here would be the
 * same defect the session grant fixed in #295.
 *
 * ### A store outage is 503, not a verdict
 *
 * A `poll` that throws is the device-code store failing, which the handler
 * answers as every grant answers a store outage: `503
 * temporarily_unavailable`, logged at error as
 * `device_code_grant_store_unavailable` (`storeOutage.mts`). None of RFC
 * 8628's four codes would be true of it, and a thrown error reached the host
 * app's error handler as a `500`. It does not say the approval is still
 * waiting: `poll` consumes an approval in the same script that reads it, and
 * one whose reply was lost is gone — the device's retry is then answered
 * `invalid_grant`, and the device starts again.
 */

import type {
	DeviceCodeStore,
	GrantContext,
	GrantHandler,
	GrantHandlerResult,
	KeyStore,
} from "@o3co/auth-provider-core";
import { generateToken, generateTokenResponse, isLifetimeSeconds } from "@o3co/auth-provider-core";
import { DEVICE_CODE_STORE_UNAVAILABLE, reportDeviceCodeStoreOutage } from "./storeOutage.mjs";

export interface DeviceCodeGrantOptions {
	readonly store: DeviceCodeStore;
	readonly keyStore: KeyStore;
	readonly accessTokenExpiresIn: number;
	readonly logger?: {
		warn(obj: Record<string, unknown>, msg: string): void;
		/** Where a store outage is reported; without it, core's console logger. */
		error?(obj: Record<string, unknown>, msg: string): void;
	};
	readonly now?: () => number;
}

const error = (status: number, code: string, description: string): GrantHandlerResult => ({
	result: { status, error: code, errorDescription: description },
});

export const createDeviceCodeGrant = (options: DeviceCodeGrantOptions): GrantHandler => {
	const now = options.now ?? Date.now;
	// The one lifetime this grant mints with, held to the rule core's
	// resolvers hold `oauth.accessToken.*` to (`isLifetimeSeconds`: a whole
	// number of seconds from 1 to a year), so building the grant by hand and
	// through `deviceGrantModule` accept the same values. `generateToken` would
	// refuse a bad one too, but only on the first poll after a user approved a
	// device; a composition fault is refused where the composition is assembled.
	const { accessTokenExpiresIn } = options;
	if (!isLifetimeSeconds(accessTokenExpiresIn)) {
		throw new RangeError(
			`createDeviceCodeGrant: accessTokenExpiresIn must be a whole number of seconds from 1 to a year (got ${String(accessTokenExpiresIn)})`,
		);
	}

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const client = ctx.authenticatedClient;
			if (client === null) {
				return error(401, "invalid_client", "Client authentication is required");
			}

			const deviceCode = ctx.body.device_code;
			if (typeof deviceCode !== "string" || deviceCode === "") {
				return error(400, "invalid_request", "device_code is required");
			}

			let outcome: Awaited<ReturnType<DeviceCodeStore["poll"]>>;
			try {
				outcome = await options.store.poll(deviceCode, now());
			} catch (err) {
				reportDeviceCodeStoreOutage(options.logger, "device_code_grant_store_unavailable", err, {
					clientId: client.clientId,
				});
				return error(
					503,
					DEVICE_CODE_STORE_UNAVAILABLE.error,
					DEVICE_CODE_STORE_UNAVAILABLE.description,
				);
			}

			switch (outcome.status) {
				case "not_found":
					// Indistinguishable from a fabricated code, deliberately. An
					// already-redeemed code lands here too, so a replayed one is
					// answered exactly as an invented one is.
					return error(400, "invalid_grant", "unknown or already-used device_code");

				case "expired":
					return error(
						400,
						"expired_token",
						"the device_code has expired; start a new device authorization request",
					);

				case "denied":
					return error(400, "access_denied", "the end user denied this authorization request");

				case "pending":
					return error(
						400,
						"authorization_pending",
						"the end user has not yet completed the authorization",
					);

				case "slow_down":
					return error(
						400,
						"slow_down",
						`polling too frequently; the interval is now ${outcome.intervalSeconds} seconds`,
					);

				case "approved":
					break;
			}

			const { authorization } = outcome;

			// The code has already been consumed by `poll` at this point, so a
			// refusal here does not leave a redeemable authorization behind. That
			// is the right direction to fail: a device whose client identity does
			// not match gets nothing, and the legitimate device gets nothing
			// either and starts over — rather than the code staying live for
			// whoever else holds it.
			if (authorization.clientId !== client.clientId) {
				options.logger?.warn(
					{ expected: authorization.clientId, presented: client.clientId },
					"device_code_client_mismatch",
				);
				return error(400, "invalid_grant", "device_code was not issued to this client");
			}

			/* c8 ignore next 4 -- `poll` only reports `approved` for a record it
			   has set a subject on; the guard is here so a future adapter that
			   forgets to cannot mint a subject-less token. */
			if (authorization.subject === undefined) {
				return error(400, "invalid_grant", "authorization carries no approving subject");
			}

			const scope = authorization.grantedScope ?? [];
			// Same audience rule the session and authorization-code grants use:
			// the client's configured resource audience, falling back to the
			// client id. Never null — an audience-less token is accepted by
			// anything that checks `aud` loosely.
			const audience = client.allowedAudiences?.[0] ?? client.clientId;

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({
						accessToken: await generateToken(
							{},
							{
								keyStore: options.keyStore,
								expiresIn: accessTokenExpiresIn,
								...(ctx.issuer === undefined ? {} : { issuer: ctx.issuer }),
								audience,
								subject: authorization.subject,
								authorizedParty: client.clientId,
								scope: scope.length > 0 ? scope.join(" ") : null,
								tokenType: "at+jwt",
								...(ctx.tokenBinding?.confirmation
									? { confirmation: ctx.tokenBinding.confirmation }
									: {}),
							},
						),
					}),
				},
			};
		},

		/**
		 * #326: this grant is a standing capability of a registration, not a
		 * per-user ceremony, so a client registered before `allowedGrantTypes`
		 * existed must not acquire it by omission.
		 */
		requiresExplicitGrantAllowlist: true,
	};
};
