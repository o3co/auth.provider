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
 * finite expiry never is, one that ends within the refresh buffer always is.
 */

import type { FederationTokens } from "@o3co/auth-provider-core";
import type { FederationTokenContext } from "./federationTokenContext.mjs";

export const refreshIsDue = (
	ctx: Pick<FederationTokenContext, "refreshBufferMs">,
	tokens: Pick<FederationTokens, "expiresAt">,
): boolean => {
	const { expiresAt } = tokens;
	// `null` is an upstream issuing no finite expiry (e.g. GitHub OAuth App
	// tokens). An expiry that names no instant compares false: it is due.
	if (expiresAt === null) return false;
	return !(expiresAt.getTime() - Date.now() > ctx.refreshBufferMs);
};
