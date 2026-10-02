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
 * Whether a stored token is refreshed before it is handed on: one with no
 * finite expiry only when the record holds a refresh token, so its answer is
 * stored with an end, capped at the maximum; one that ends within the refresh
 * buffer is, unless it is known to be obtained less than half its lifetime
 * ago and has at least the refresh floor left. That rule only ever delays a refresh: an
 * `obtainedAt` that is `undefined`, or that core's `judgeHeldUpstreamToken` does
 * not believe (dated more than the floor ahead of this replica's clock, or
 * not before its own end), leaves the buffer rule alone. It reads the
 * record's instants on this replica's clock, so it assumes replicas' clocks
 * agree to within the floor.
 */

import { type FederationTokens, judgeHeldUpstreamToken } from "@o3co/auth-provider-core";
import type { FederationTokenContext } from "./federationTokenContext.mjs";
import { isUsableToken } from "./federationTokenCredential.mjs";
import { REFRESH_FLOOR_MS } from "./federationTokenRefreshAnswer.mjs";

export const refreshIsDue = (
	ctx: Pick<FederationTokenContext, "refreshBufferMs">,
	tokens: Pick<FederationTokens, "expiresAt" | "obtainedAt" | "refreshToken">,
): boolean => {
	const { expiresAt, obtainedAt } = tokens;
	// `null` is an upstream that stated no finite expiry. Without a refresh
	// token (e.g. GitHub OAuth App tokens) it is served as stored. An expiry
	// that names no instant compares false: it is due.
	if (expiresAt === null) return isUsableToken(tokens.refreshToken);
	const now = Date.now();
	const remainingMs = expiresAt.getTime() - now;
	if (remainingMs > ctx.refreshBufferMs) return false;
	// Never handed on with less left than a refresh answer is accepted with.
	if (obtainedAt === undefined || remainingMs < REFRESH_FLOOR_MS) return true;
	// Never refreshed before it is half spent, so a lifetime shorter than the
	// buffer is not refreshed on every request. A token not believed reads as
	// half spent: the buffer rule stands. The allowance is the replicas' clock
	// agreement, not the buffer: a writer dated further ahead would keep its
	// token from being refreshed until it reached the floor.
	return judgeHeldUpstreamToken({ obtainedAt, expiresAt }, { now, allowanceMs: REFRESH_FLOOR_MS })
		.halfSpent;
};
