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
 * §3.5. The device polls here until its user answers elsewhere.
 *
 * RFC 8628's four error codes must stay distinct, since client libraries
 * branch on them: `authorization_pending` (keep polling), `slow_down` (§3.5:
 * the interval grows by 5 seconds), `access_denied` (the user refused),
 * `expired_token` (the window closed). Collapsing any of them into
 * `invalid_grant` turns a clear outcome into endless retries.
 *
 * - The polling interval is enforced atomically in `DeviceCodeStore.poll`; a
 *   read-compare-write here would let concurrent polls both pass.
 * - A code is redeemable only by the client it was issued to, read from the
 *   authenticated client, never the attacker-controlled body; otherwise a
 *   leaked code lets another client redeem the user's approval.
 * - A poll that presents a DPoP proof or client certificate gets a token
 *   bound to it (`ownedConfirmation`), and `generateTokenResponse` derives
 *   `token_type` from that binding (`DPoP` for `cnf.jkt`, RFC 9449 §5;
 *   `Bearer` for mTLS, RFC 8705 §3).
 * - With `subjectRevocation` wired, an approval at or before the subject's
 *   sessions boundary (`coveredByRevocationBoundary`, with `verifyJwt`'s
 *   skew), or one with no recorded `approvedAtMs` while a boundary is in
 *   force, is `invalid_grant`. The approval check alone is not enough: a
 *   stolen session could approve codes ahead and redeem them after the
 *   victim's credential change. An unreadable boundary is 503
 *   `temporarily_unavailable`.
 * - A throwing `poll` is a store outage, answered 503
 *   `temporarily_unavailable` — none of the four codes is true of it.
 * - A wired `grantPolicy` is consulted on the approval once its client is
 *   checked, before the revocation read and the minting instant, through
 *   core's `evaluateGrantPolicy`: deny is 400 with the policy's error when
 *   it is a token-endpoint code (RFC 6749 §5.2's, `invalid_target`) or
 *   RFC 8628 §3.5's terminal `access_denied` or `expired_token`, and
 *   `invalid_grant` otherwise (never `authorization_pending` or `slow_down`:
 *   the approval is spent), a
 *   throw is 503, a scope or audience past the approval or `allowedAudiences`
 *   is 500. It may only narrow; its audience, within `allowedAudiences`, is
 *   `aud`.
 * - The approved record is read through core's `readDeviceAuthorization`
 *   before any of it is used. A record it refuses — a field whose read
 *   throws or that is not what `DeviceAuthorization` declares, an
 *   `authTimeMs` that is not whole epoch milliseconds included — is
 *   `invalid_grant`, logged at error: the approval is already spent.
 * - An `approvedAtMs` further ahead of the minting clock than
 *   `DEFAULT_CLOCK_SKEW_MS` is `invalid_grant`, warned: an approval from the
 *   future would postdate any sessions boundary.
 * - The token carries the approval's recorded `amr` and its `authTimeMs` as
 *   `auth_time`, read against the minting clock with `authTimeAt`; the same
 *   instant is its `iat`. Neither recorded, neither is stamped. An
 *   `authTimeMs` that clock cannot read is `invalid_grant`; an `amr` the
 *   reader reads as none is stamped as none. No `acr`: device verification
 *   selects none.
 *
 * `poll` consumes an approval in the same step that reads it.
 * `authorization_pending` and `slow_down` leave the code in place and the device
 * keeps polling; once an approval is consumed, a refusal that follows it or a
 * lost reply means the device starts over.
 */

import type {
	DeviceCodeStore,
	EvaluateGrantPolicyOptions,
	GrantContext,
	GrantError,
	GrantHandler,
	GrantHandlerResult,
	GrantPolicyHook,
	KeyStore,
	SubjectRevocation,
} from "@o3co/auth-provider-core";
import {
	authTimeAt,
	boundPolicyAudience,
	consoleLogger,
	coveredByRevocationBoundary,
	DEFAULT_CLOCK_SKEW_MS,
	DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
	evaluateGrantPolicy,
	generateToken,
	generateTokenResponse,
	isLifetimeSeconds,
	ownedConfirmation,
	readDeviceAuthorization,
} from "@o3co/auth-provider-core";
import {
	DEVICE_CODE_STORE_UNAVAILABLE,
	reportDeviceCodeStoreOutage,
	reportUnreadableDeviceAuthorization,
} from "./storeOutage.mjs";
import { DEVICE_CODE_GRANT_TYPE } from "./types.mjs";

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
	/**
	 * The subject's sessions boundary — see the file header. Optional as it
	 * is at every surface that reads it.
	 */
	readonly subjectRevocation?: Pick<SubjectRevocation, "revokedBefore">;
	/**
	 * The deployment's grant policy, consulted at the poll. A required key, not
	 * a required value: a grant built without one says so with `undefined`.
	 */
	readonly grantPolicy: GrantPolicyHook | undefined;
}

const error = (status: number, code: string, description: string): GrantHandlerResult => ({
	result: { status, error: code, errorDescription: description },
});

/**
 * Where core writes a policy's lines, object-first: its outage and
 * invalid-decision lines at error, a deny it rewrites at warn. A channel the
 * logger lacks is left to core's console logger.
 */
const policyLoggerOf = (
	logger: DeviceCodeGrantOptions["logger"],
): EvaluateGrantPolicyOptions["logger"] => {
	if (logger === undefined) return undefined;
	const writeError =
		typeof logger.error === "function"
			? logger.error.bind(logger)
			: consoleLogger.error.bind(consoleLogger);
	const writeWarn = typeof logger.warn === "function" ? logger.warn.bind(logger) : undefined;
	return {
		error: (obj: unknown, msg?: unknown) => writeError(obj as Record<string, unknown>, String(msg)),
		...(writeWarn !== undefined
			? {
					warn: (obj: unknown, msg?: unknown) =>
						writeWarn(obj as Record<string, unknown>, String(msg)),
				}
			: {}),
	};
};

/** A policy refusal; an outage says what any refusal after `poll` means for the device. */
const policyRefusal = (result: GrantError): GrantHandlerResult =>
	result.status === 503
		? error(
				503,
				result.error,
				"the grant policy is unavailable; start a new device authorization request",
			)
		: { result };

export const createDeviceCodeGrant = (options: DeviceCodeGrantOptions): GrantHandler => {
	const now = options.now ?? Date.now;
	// Held to core's `isLifetimeSeconds` rule so hand-built and module-built
	// grants accept the same values, and a bad value fails at composition
	// rather than on the first approved poll.
	const { accessTokenExpiresIn } = options;
	if (!isLifetimeSeconds(accessTokenExpiresIn)) {
		throw new RangeError(
			`createDeviceCodeGrant: accessTokenExpiresIn must be a whole number of seconds from 1 to a year (got ${String(accessTokenExpiresIn)})`,
		);
	}
	const policyLogger = policyLoggerOf(options.logger);

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

			// See the file header: nothing of the store's object is read but this.
			const reading = readDeviceAuthorization(outcome.authorization);
			if (!reading.ok) {
				reportUnreadableDeviceAuthorization(
					options.logger,
					"device_code_grant_record_unreadable",
					reading,
					{ clientId: client.clientId },
				);
				return error(
					400,
					"invalid_grant",
					"the approval cannot be read; start a new device authorization request",
				);
			}
			const { authorization } = reading;

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

			// See the file header. The approval is the ceiling, and the policy is
			// handed a copy of it. Ahead of the revocation read and the minting
			// instant, so neither is stale by the policy's latency.
			let scope: readonly string[] = authorization.grantedScope ?? [];
			let policyAudience: string | null = null;
			if (options.grantPolicy !== undefined) {
				const policy = await evaluateGrantPolicy(
					options.grantPolicy,
					{
						grantType: DEVICE_CODE_GRANT_TYPE,
						clientId: client.clientId,
						subject: authorization.subject,
						requestedScope: scope.length > 0 ? [...scope] : undefined,
					},
					{ ip: ctx.ip, userAgent: ctx.userAgent, issuer: ctx.issuer ?? "" },
					scope,
					// The poll has spent the approval: a refusal ends the device's
					// polling. RFC 8628 §3.5's terminal codes pass; anything else is
					// `invalid_grant`, never a keep-polling code.
					{
						logger: policyLogger,
						denyFallback: "invalid_grant",
						denyAllowed: ["access_denied", "expired_token"],
					},
				);
				if (!policy.ok) return policyRefusal(policy.result);
				scope = policy.scopes;
				const bounded = boundPolicyAudience(policy.decision, client.allowedAudiences ?? []);
				if (!bounded.ok) return { result: bounded.result };
				policyAudience = bounded.audience;
			}

			// See the file header: a revocation stamped between the approval and
			// this poll.
			const revocation = options.subjectRevocation;
			if (revocation !== undefined) {
				let revoked: boolean;
				try {
					const boundary = await revocation.revokedBefore(authorization.subject);
					if (boundary !== null && !(boundary instanceof Date)) {
						throw new TypeError("the sessions boundary is neither a date nor null");
					}
					revoked =
						boundary !== null &&
						(authorization.approvedAtMs === undefined ||
							coveredByRevocationBoundary(
								new Date(authorization.approvedAtMs),
								boundary,
								DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
							));
				} catch (err) {
					reportDeviceCodeStoreOutage(
						options.logger,
						"device_code_grant_revocation_unavailable",
						err,
						{
							store: "revocation_boundary",
							step: "read",
							clientId: client.clientId,
						},
					);
					// Its own words, not the device-code store's: that store
					// answered, and this poll consumed the approval, so a retry
					// is `invalid_grant` — the device starts again.
					return error(
						503,
						"temporarily_unavailable",
						"the revocation boundary is unavailable; start a new device authorization request",
					);
				}
				if (revoked) {
					return error(
						400,
						"invalid_grant",
						"the approval predates a revocation of the subject's sessions; start a new device authorization request",
					);
				}
			}

			// One minting instant: `auth_time` is read against it and stamped as
			// `iat`, so `auth_time` is never after `iat` — see the file header.
			const mintingNow = now();
			const { approvedAtMs } = authorization;
			if (approvedAtMs !== undefined && approvedAtMs > mintingNow + DEFAULT_CLOCK_SKEW_MS) {
				options.logger?.warn(
					{ clientId: client.clientId, aheadMs: approvedAtMs - mintingNow },
					"device_approval_ahead_of_clock",
				);
				return error(
					400,
					"invalid_grant",
					"the approval's time is ahead of this server's clock; start a new device authorization request",
				);
			}
			const { authTimeMs } = authorization;
			const authTime =
				authTimeMs === undefined ? undefined : authTimeAt(new Date(authTimeMs), mintingNow);
			if (authTimeMs !== undefined && authTime === undefined) {
				options.logger?.warn(
					{ clientId: client.clientId, aheadMs: authTimeMs - mintingNow },
					"auth_time_ahead_of_clock",
				);
				return error(
					400,
					"invalid_grant",
					"the approving session's authentication time cannot be read; start a new device authorization request",
				);
			}
			const amr = authorization.amr;

			// The policy's audience, else the rule the session and
			// authorization-code grants use: the client's configured resource
			// audience, falling back to the client id. Never null — an
			// audience-less token is accepted by anything that checks `aud` loosely.
			const audience = policyAudience ?? client.allowedAudiences?.[0] ?? client.clientId;
			// See the file header: the owned member only, and the envelope's
			// `token_type` follows it.
			const confirmation = ownedConfirmation(ctx.tokenBinding);

			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({
						accessToken: await generateToken(
							{
								...(amr === undefined ? {} : { amr }),
								...(authTime === undefined ? {} : { auth_time: authTime }),
							},
							{
								keyStore: options.keyStore,
								expiresIn: accessTokenExpiresIn,
								...(ctx.issuer === undefined ? {} : { issuer: ctx.issuer }),
								audience,
								subject: authorization.subject,
								authorizedParty: client.clientId,
								scope: scope.length > 0 ? scope.join(" ") : null,
								tokenType: "at+jwt",
								issuedAt: Math.floor(mintingNow / 1000),
								...(confirmation ? { confirmation } : {}),
							},
						),
					}),
				},
			};
		},

		/**
		 * A standing capability of a registration, so a client that declares no
		 * `allowedGrantTypes` must not acquire it by omission.
		 */
		requiresExplicitGrantAllowlist: true,
	};
};
