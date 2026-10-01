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
	FederationTokenStore,
	Logger,
	RefreshTokenFamilyRevocation,
	SessionFamilyIndex,
	SessionFederationIndex,
	SessionRPRegistry,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import { loggableError, supportsSessionEnd } from "@o3co/auth-provider-core";

export interface CascadeLogoutOptions {
	readonly sid: string;
	/**
	 * The session's `expiresAt`. Pass it whenever the caller holds the
	 * session. With it, an index with the session-end capability marks the
	 * session ended at step 1, so a family added after the listing is refused
	 * rather than left unrevoked. Without it, the families are only listed.
	 */
	readonly expiresAt?: Date;
	/**
	 * The session's families as `beginLogout` read them when it ended the
	 * session. Given, step 1 reads nothing and revokes these: no family joins
	 * an ended session.
	 */
	readonly familyIds?: ReadonlyArray<string>;
	readonly refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation;
	readonly federationTokenStore: FederationTokenStore;
	readonly userSessionStore: UserSessionStore;
	readonly sessionRPRegistry: SessionRPRegistry;
	readonly sessionFamilyIndex: SessionFamilyIndex;
	readonly sessionFederationIndex: SessionFederationIndex;
	/**
	 * Defaults to `console`. Each failed operation is one warn line with the
	 * error's projection: `logout_cascade_operation_failed` for a step-2
	 * fanout operation (the cascade then fails, and the caller answers and
	 * logs the outage), `logout_cascade_cleanup_failed` for a cleanup.
	 */
	readonly logger?: Logger;
}

export type CascadeLogoutResult =
	| { readonly outcome: "done" }
	| {
			readonly outcome: "failed";
			readonly step: 1 | 2 | 4;
			readonly errors: ReadonlyArray<unknown>;
	  };

/**
 * Runs the logout store cascade in a fixed order:
 *
 *   1. Read the fanout context: the families `beginLogout` read, when given
 *      (`familyIds`); else `sessionFamilyIndex.endSession` when the
 *      index has the session-end capability and `expiresAt` is given, which
 *      marks the session ended before it lists; `listFamilyIds` otherwise.
 *      Failure returns `failed` step 1; nothing else ran but, possibly, the
 *      mark, and a retry is safe: `endSession` is idempotent.
 *   2. Fanout, collect-and-tally: `revokeFamily` per family, then
 *      `federationTokenStore.removeBySid`. Any failure returns `failed` step 2
 *      with every error, before step 3: cleanup would erase the bookkeeping a
 *      retry needs and mark the cascade complete over an un-revoked family.
 *   3. Reverse-index cleanup (RP registry, family index, federation index),
 *      best-effort: logged and continued, orphans bounded by TTL. Never fails,
 *      hence no step 3 in the result. Without the mark (no `expiresAt`, or an
 *      index without the capability), a family a code exchange adds after
 *      step 1 is dropped from the index here unrevoked.
 *   4. `userSessionStore.delete`, last, which must succeed; failure returns
 *      `failed` step 4.
 *
 * A cascade that fails after the mark is written leaves the session
 * half-ended: it still exists, and its code exchanges are refused until a
 * retry completes the logout or the mark lapses (fail-closed).
 *
 * The caller maps `failed` to 503, invokes `broadcastBackchannelLogout`
 * (best-effort, never throws) before this, and runs front-channel and IdP
 * logout separately.
 *
 * @param opts.logger - Defaults to `console`.
 */
export async function cascadeLogout(opts: CascadeLogoutOptions): Promise<CascadeLogoutResult> {
	const logger = opts.logger ?? console;

	// Step 1: read fanout context.
	const index = opts.sessionFamilyIndex;
	let familyIds: ReadonlyArray<string>;
	try {
		familyIds =
			opts.familyIds ??
			(opts.expiresAt !== undefined && supportsSessionEnd(index)
				? await index.endSession(opts.sid, opts.expiresAt)
				: await index.listFamilyIds(opts.sid));
	} catch (error) {
		return { outcome: "failed", step: 1, errors: [error] };
	}

	// Step 2: fanout, collect-and-tally. Any failure halts before step 3.
	const stepTwoFailures: unknown[] = [];

	for (const familyId of familyIds) {
		try {
			await opts.refreshTokenFamilyRevocation.revokeFamily(familyId);
		} catch (error) {
			stepTwoFailures.push(error);
			logger.warn(
				{ operation: "revoke_family", sid: opts.sid, familyId, err: loggableError(error) },
				"logout_cascade_operation_failed",
			);
		}
	}

	try {
		await opts.federationTokenStore.removeBySid(opts.sid);
	} catch (error) {
		stepTwoFailures.push(error);
		logger.warn(
			{ operation: "remove_federation_tokens", sid: opts.sid, err: loggableError(error) },
			"logout_cascade_operation_failed",
		);
	}

	if (stepTwoFailures.length > 0) {
		return { outcome: "failed", step: 2, errors: stepTwoFailures };
	}

	// Step 3: reverse-index cleanup, best-effort; orphans are bounded by TTL.
	await opts.sessionRPRegistry.removeBySid(opts.sid).catch((error) => {
		logger.warn(
			{ operation: "remove_rp_registrations", sid: opts.sid, err: loggableError(error) },
			"logout_cascade_cleanup_failed",
		);
	});
	await opts.sessionFamilyIndex.removeBySid(opts.sid).catch((error) => {
		logger.warn(
			{ operation: "remove_family_index", sid: opts.sid, err: loggableError(error) },
			"logout_cascade_cleanup_failed",
		);
	});
	await opts.sessionFederationIndex.removeBySid(opts.sid).catch((error) => {
		logger.warn(
			{ operation: "remove_federation_index", sid: opts.sid, err: loggableError(error) },
			"logout_cascade_cleanup_failed",
		);
	});

	// Step 4: primary invalidation, which must succeed.
	try {
		await opts.userSessionStore.delete(opts.sid);
	} catch (error) {
		return { outcome: "failed", step: 4, errors: [error] };
	}

	// Clear the family index again after the delete: a family added between
	// step 3 and step 4 (one the ended mark refused, or one added on an index
	// without the mark) would otherwise stay until the index's TTL. Idempotent
	// and best-effort; `removeBySid` keeps the ended mark.
	await opts.sessionFamilyIndex.removeBySid(opts.sid).catch((error) => {
		logger.warn(
			{ operation: "remove_family_index_after_delete", sid: opts.sid, err: loggableError(error) },
			"logout_cascade_cleanup_failed",
		);
	});

	return { outcome: "done" };
}
