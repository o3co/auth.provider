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
 * finite expiry never is; one that ends within the refresh buffer is, unless
 * it is known to be obtained less than half its lifetime ago. That rule only
 * ever delays a refresh: an `obtainedAt` that is absent, or that core's
 * `judgeHeldUpstreamToken` does not believe, leaves the buffer rule alone.
 */

import { type FederationTokens, judgeHeldUpstreamToken } from "@o3co/auth-provider-core";
import type { FederationTokenContext } from "./federationTokenContext.mjs";

export const refreshIsDue = (
	ctx: Pick<FederationTokenContext, "refreshBufferMs">,
	tokens: Pick<FederationTokens, "expiresAt" | "obtainedAt">,
): boolean => {
	const { expiresAt, obtainedAt } = tokens;
	// `null` is an upstream issuing no finite expiry (e.g. GitHub OAuth App
	// tokens). An expiry that names no instant compares false: it is due.
	if (expiresAt === null) return false;
	const now = Date.now();
	if (expiresAt.getTime() - now > ctx.refreshBufferMs) return false;
	if (obtainedAt === undefined) return true;
	// Never refreshed before it is half spent, so a lifetime shorter than the
	// buffer is not refreshed on every request. A token not believed reads as
	// half spent: the buffer rule stands.
	return judgeHeldUpstreamToken(
		{ obtainedAt, expiresAt },
		{ now, allowanceMs: ctx.refreshBufferMs },
	).halfSpent;
};
