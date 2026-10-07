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
 * Refreshing a token that is due (`refreshIsDue`): the provider has to be
 * able to refresh and the record to hold a refresh token. The record's lock,
 * when the store has one, is taken before the re-read and released, always,
 * once the answer is sent. A record the re-read finds gone is answered as
 * unlinked, and neither refreshed nor written back. Every write lands only on
 * the record the refresh was made from (`federationTokenRecord.mts`).
 */

import {
	loggableError,
	sanitizeErrorText,
	supportsLock,
	supportsRefresh,
} from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
import { readRecord, type StoredRecord, serveHeld, serveStored } from "./federationTokenRecord.mjs";
import { readRefreshAnswer } from "./federationTokenRefreshAnswer.mjs";
import { refreshIsDue } from "./federationTokenRefreshDue.mjs";
import { answerRefreshFailure } from "./federationTokenRefreshFailure.mjs";
import { recordRefresh } from "./federationTokenRefreshRecord.mjs";

/** Step 11. `read` is the record as read before the lock. */
export const refreshStoredTokens = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	read: StoredRecord,
): Promise<Response> => {
	const { opts, res, name, federation, logger, storeUnavailable, maxTokenLifetimeMs } = ctx;
	const { sid, azp } = caller;

	// Step 11: Refresh path.

	// 11a: Get provider and check supportsRefresh.
	const provider = opts.getFederationProviders()?.get(name);
	if (!supportsRefresh(provider)) {
		// The deployment's to fix, not a request's: every refresh through this
		// federation is answered 503 until the provider is configured.
		logger.error({ federation }, "federation_token_refresh_unsupported");
		return res.status(503).json({
			error: "refresh_not_supported",
			error_description: sanitizeErrorText(`federation '${name}' does not support token refresh`),
		});
	}

	// 11b: refreshToken must be present.
	if (!read.value.refreshToken) {
		return res.status(410).json({
			error: "refresh_token_absent",
			error_description: "no refresh token available for this federation",
		});
	}

	// 11c: Acquire lock if supported.
	let release: (() => Promise<void>) | undefined;
	if (supportsLock(opts.federationTokenStore)) {
		let lockResult: Awaited<ReturnType<typeof opts.federationTokenStore.acquireLock>>;
		try {
			lockResult = await opts.federationTokenStore.acquireLock({
				sid,
				federationName: name,
			});
		} catch (error) {
			storeUnavailable(federation, "federation_token", "acquire_lock", error);
			return res.status(503).json({
				error: "temporarily_unavailable",
				error_description: "federation token store unavailable",
			});
		}
		if (!lockResult.acquired) {
			// Contention, not an outage: another refresh of this record holds
			// the lock. Warn, so contention that persists is seen — who waited
			// (the federation, the client, the session), never a token.
			logger.warn({ federation, clientId: azp, sid }, "federation_token_lock_timeout");
			return res.status(503).json({
				error: "lock_timeout",
				error_description: "could not acquire refresh lock, try again",
			});
		}
		release = lockResult.release;
	}

	try {
		// The record the refresh is made from, and the only one its writes may
		// land on: the post-lock re-read when there is a lock, so the IdP call
		// uses the freshest refresh_token and id_token.
		let current = read;

		// 11d: Re-read after the lock to detect a concurrent refresh, or a
		// logout or unlink that removed the record (answered `404`, and neither
		// refreshed nor written back).
		if (release !== undefined) {
			const fresh = await readRecord(ctx, caller, "get_after_lock");
			if (fresh === null) return res;
			if (!refreshIsDue(ctx, fresh.value)) {
				// Another caller refreshed, or the token is not due: served as on
				// the fast path, without calling the IdP, but only while the
				// session is still live and the record still the one re-read,
				// since the lock wait spans the other caller's upstream call.
				// Awaited inside the `try`, so the lock is released after the
				// answer.
				return await serveHeld(ctx, caller, fresh, () => serveStored(ctx, caller, fresh));
			}
			current = fresh;
		}

		// The post-lock re-read may lack a refresh token too (a concurrent
		// revoke, or a rotation without one): 410 gives a precise re-auth
		// signal instead of an opaque upstream failure.
		if (!current.value.refreshToken) {
			return res.status(410).json({
				error: "refresh_token_absent",
				error_description: "no refresh token available for this federation (post-lock re-read)",
			});
		}

		// A refresh of this record answered `500 refresh_failed` within the
		// back-off window: answered the same without calling the upstream.
		if (
			ctx.refreshBackoff.holds(
				{ sid, federationName: name, accessToken: current.value.accessToken },
				Date.now(),
			)
		) {
			logger.info({ federation }, "federation_token_refresh_backed_off");
			return res.status(500).json({
				error: "refresh_failed",
				error_description: "federation token refresh failed",
			});
		}

		// 11e: refresh with the freshest snapshot. The lock is held across the
		// IdP call; its TTL should cover the IdP timeout, else a second waiter
		// also calls the IdP. Each write lands only on the record it refreshed
		// from, so at most one of theirs lands. One that the upstream refuses
		// `invalid_grant` (the refresh token the other spent) still ends the
		// record under the lapsed lock, and the other's refresh is then
		// dropped as removed: the user reconnects.
		let refreshed: Awaited<ReturnType<typeof provider.refreshToken>>;
		const calledAt = Date.now();
		try {
			refreshed = await provider.refreshToken(current.value.refreshToken);
		} catch (error) {
			// Awaited inside the `try`, so the lock is released after the answer.
			return await answerRefreshFailure(ctx, caller, current, release !== undefined, error);
		}

		// Awaited inside the `try`, so the lock is released after the answer.
		return await recordRefresh(
			ctx,
			caller,
			current,
			readRefreshAnswer(refreshed, current.value, { calledAt, maxTokenLifetimeMs }),
		);
	} finally {
		// 11g: Release lock if acquired.
		if (release !== undefined) {
			try {
				await release();
			} catch (error) {
				logger.warn(
					{
						federation,
						store: "federation_token",
						step: "release_lock",
						err: loggableError(error),
					},
					"federation_token_lock_release_failed",
				);
			}
		}
	}
};
