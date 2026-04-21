/*
 * Copyright 2026 1o1 Co. Ltd.
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

import type {
	FederationTokenStoreBase,
	RefreshTokenStoreBase,
	UserSessionStoreBase,
} from "@o3co/auth-provider-core";

/**
 * Minimal structural logger interface for cascadeLogout.
 * Accepts `console` and any structured logger (pino, winston, etc.)
 * with a compatible `warn(message, ...args)` signature.
 */
export interface CascadeLogoutLogger {
	warn(message: string, ...args: unknown[]): void;
}

export interface CascadeLogoutOptions {
	readonly sid: string;
	readonly familyIds: ReadonlyArray<string>;
	readonly refreshTokenStore: RefreshTokenStoreBase;
	readonly federationTokenStore: FederationTokenStoreBase;
	readonly userSessionStore: UserSessionStoreBase;
	/**
	 * Optional structured logger for the step-2 best-effort warning.
	 * Defaults to `console`. Provide a pino/winston/etc instance with a compatible
	 * `warn(message, ...args)` signature to route failures into your observability stack.
	 */
	readonly logger?: CascadeLogoutLogger;
}

export type CascadeLogoutResult =
	| { readonly outcome: "done" }
	| { readonly outcome: "failed"; readonly step: 1 | 2 | 3; readonly error: unknown };

/**
 * Executes the three-step logout cascade in the fixed order mandated by spec
 * Section 14.2:
 *   1. revokeFamily (all families) — throw ⇒ 503 (steps 2+3 skipped; retry safe).
 *   2. deleteBySession (federation tokens) — best-effort; throw ⇒ warn + continue.
 *      Orphaned federation tokens eventually GC by TTL.
 *   3. delete (session record) — throw ⇒ 503 (steps 1+2 are idempotent, retry converges).
 *
 * Caller responsibilities:
 *   - Map `outcome: "failed"` to HTTP 503.
 *   - Run Back-Channel / Front-Channel / IdP-logout phases separately — this helper
 *     only handles the store cascade.
 *
 * @param opts.logger - Optional structured logger for the step-2 best-effort warning.
 *   Defaults to `console`. Provide a pino/winston/etc instance with a compatible
 *   `warn(message, ...args)` signature to route failures into your observability stack.
 */
export async function cascadeLogout(opts: CascadeLogoutOptions): Promise<CascadeLogoutResult> {
	// Step 1: revoke each family.
	for (const familyId of opts.familyIds) {
		try {
			await opts.refreshTokenStore.revokeFamily(familyId);
		} catch (error) {
			return { outcome: "failed", step: 1, error };
		}
	}

	// Step 2: delete federation tokens. Best-effort.
	try {
		await opts.federationTokenStore.deleteBySession(opts.sid);
	} catch (error) {
		const logger = opts.logger ?? console;
		logger.warn(
			`cascadeLogout: FederationTokenStore.deleteBySession(${opts.sid}) failed (continuing):`,
			error,
		);
	}

	// Step 3: delete session record.
	try {
		await opts.userSessionStore.delete(opts.sid);
	} catch (error) {
		return { outcome: "failed", step: 3, error };
	}

	return { outcome: "done" };
}
