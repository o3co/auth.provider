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
 * Refreshing a token that expires within the buffer: the provider has to be
 * able to refresh and the record to hold a refresh token. The record's lock,
 * when the store has one, is taken before the re-read and released, always,
 * once the answer is sent.
 */

import {
	type FederationTokens,
	loggableError,
	sanitizeErrorText,
	supportsLock,
	supportsRefresh,
} from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
import { isDisclosable, refuseUndisclosableTokenType } from "./federationTokenDisclosure.mjs";
import { readRefreshAnswer } from "./federationTokenRefreshAnswer.mjs";
import { refreshIsDue } from "./federationTokenRefreshDue.mjs";
import { answerRefreshFailure } from "./federationTokenRefreshFailure.mjs";
import { recordRefresh } from "./federationTokenRefreshRecord.mjs";
import { answerToken } from "./federationTokenSuccess.mjs";

/** Step 11. `tokens` is the record as read before the lock. */
export const refreshStoredTokens = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	tokens: FederationTokens,
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
	if (!tokens.refreshToken) {
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
		// currentTokens tracks the freshest snapshot of stored federation tokens.
		// It starts as the pre-lock read and is updated to the post-lock re-read
		// value (11d) so that all downstream IdP calls and store writes use the
		// most up-to-date refresh_token and id_token — never a stale pre-lock snapshot.
		let currentTokens = tokens;

		// 11d: Re-read tokens after lock acquisition to detect concurrent refresh.
		if (release !== undefined) {
			let freshTokens: Awaited<ReturnType<typeof opts.federationTokenStore.get>>;
			try {
				freshTokens = await opts.federationTokenStore.get(sid, name);
			} catch (error) {
				storeUnavailable(federation, "federation_token", "get_after_lock", error);
				return res.status(503).json({
					error: "temporarily_unavailable",
					error_description: "federation token store unavailable",
				});
			}
			if (freshTokens && !refreshIsDue(ctx, freshTokens)) {
				// Another caller refreshed, or there is no finite expiry: return
				// the stored token without calling the IdP, judging its type as on
				// the fast path.
				if (!isDisclosable(freshTokens)) {
					return refuseUndisclosableTokenType(ctx, caller, freshTokens.tokenType);
				}
				// Awaited inside the `try`, so the lock is released after the answer.
				return await answerToken(ctx, caller, freshTokens, false);
			}
			// Update to the post-lock re-read value (may be freshTokens or null if
			// the store returned null; in either case currentTokens keeps the pre-lock
			// snapshot when freshTokens is null, which is the safest fallback).
			if (freshTokens) {
				currentTokens = freshTokens;
			}
		}

		// The post-lock re-read may lack a refresh token too (a concurrent
		// revoke, or a rotation without one): 410 gives a precise re-auth
		// signal instead of an opaque upstream failure.
		if (!currentTokens.refreshToken) {
			return res.status(410).json({
				error: "refresh_token_absent",
				error_description: "no refresh token available for this federation (post-lock re-read)",
			});
		}

		// 11e: refresh with the freshest snapshot. The lock is held across the
		// IdP call; its TTL should cover the IdP timeout, else a second waiter
		// also calls the IdP — harmless, since `update` is atomic and the last
		// write wins.
		let refreshed: Awaited<ReturnType<typeof provider.refreshToken>>;
		const calledAt = Date.now();
		try {
			refreshed = await provider.refreshToken(currentTokens.refreshToken);
		} catch (error) {
			// Awaited inside the `try`, so the lock is released after the answer.
			return await answerRefreshFailure(ctx, caller, error);
		}

		// Awaited inside the `try`, so the lock is released after the answer.
		return await recordRefresh(
			ctx,
			caller,
			currentTokens,
			readRefreshAnswer(refreshed, currentTokens, { calledAt, maxTokenLifetimeMs }),
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
