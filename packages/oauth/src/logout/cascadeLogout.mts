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
	Logger,
	RefreshTokenFamilyRevocation,
	SessionFamilyIndex,
	SessionFederationIndex,
	SessionRPRegistry,
	UserSessionStore,
} from "@o3co/auth-provider-core";

export interface CascadeLogoutOptions {
	readonly sid: string;
	readonly refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation;
	readonly federationTokenStore: FederationTokenStoreBase;
	readonly userSessionStore: UserSessionStore;
	readonly sessionRPRegistry: SessionRPRegistry;
	readonly sessionFamilyIndex: SessionFamilyIndex;
	readonly sessionFederationIndex: SessionFederationIndex;
	/**
	 * Optional structured logger for warning emissions on best-effort ops.
	 * Defaults to `console`. Provide a pino/winston/etc instance with a compatible
	 * `warn(message, ...args)` signature to route failures into your observability stack.
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
 * Executes the four-step logout cascade in the fixed order mandated by A4 §6.2:
 *   Step 1: Read fanout context — sessionFamilyIndex.listFamilyIds(sid).
 *           Fail → return failed step:1 (steps 2–4 skipped; retry safe).
 *   Step 2: Fanout — collect-and-tally.
 *           - revokeFamily loop (per family; continues on per-op failure, tallies errors)
 *           - federationTokenStore.deleteBySession (tallied on failure)
 *           If ANY failure → return failed step:2 with all errors (HALT before step 3).
 *           §6.2 critical rule: HALT preserves bookkeeping for retry. Running step 3
 *           would erase reverse-index entries and silently mark the cascade complete
 *           despite an un-revoked family.
 *   Step 3: Reverse-index cleanup — only if step 2 fully succeeded. Per-op best-effort
 *           (log + continue; orphan entries bounded by TTL).
 *           - sessionRPRegistry.removeBySid
 *           - sessionFamilyIndex.removeBySid
 *           - sessionFederationIndex.removeBySid
 *           Never returns failed (step 3 best-effort; hence step range is 1|2|4 not 1|2|3|4).
 *   Step 4: Primary invalidation — userSessionStore.delete LAST (must succeed).
 *           Fail → return failed step:4.
 *
 * Note: broadcastBackchannelLogout is invoked by routes/logout.mts BEFORE cascadeLogout
 * (it is "best-effort — never throws" per its own contract), so its position is
 * functionally equivalent to being a no-throw step-2 op inside the cascade per §6.2 model.
 * Moving it here would require pulling in sub/issuer/keyStore/fetchImpl/auditSink as new
 * deps — a surface change beyond this helper's scope.
 *
 * Caller responsibilities:
 *   - Map `outcome: "failed"` to HTTP 503.
 *   - Invoke broadcastBackchannelLogout (best-effort) BEFORE calling this function.
 *   - Run Front-Channel / IdP-logout phases separately — this helper only handles
 *     the store cascade.
 *
 * @param opts.logger - Optional structured logger for best-effort warning emissions.
 *   Defaults to `console`.
 */
export async function cascadeLogout(opts: CascadeLogoutOptions): Promise<CascadeLogoutResult> {
	const logger = opts.logger ?? console;

	// §6.2 Step 1: read fanout context.
	let familyIds: ReadonlyArray<string>;
	try {
		familyIds = await opts.sessionFamilyIndex.listFamilyIds(opts.sid);
	} catch (error) {
		return { outcome: "failed", step: 1, errors: [error] };
	}

	// §6.2 Step 2: fanout — collect-and-tally.
	// Per §6.2 critical rule: HALT before Step 3 if ANY op failed (preserves
	// bookkeeping for retry — orphan family revocation MUST be visible to a
	// retry attempt; running Step 3 would erase that bookkeeping and silently
	// mark the cascade complete despite an un-revoked family).
	//
	// Note: broadcastBackchannelLogout is invoked by routes/logout.mts BEFORE
	// cascadeLogout (it's "best-effort — never throws" per its own contract),
	// so it is functionally equivalent to being a no-throw Step 2 op here.
	const stepTwoFailures: unknown[] = [];

	for (const familyId of familyIds) {
		try {
			await opts.refreshTokenFamilyRevocation.revokeFamily(familyId);
		} catch (error) {
			stepTwoFailures.push(error);
			logger.warn(
				`cascadeLogout: refreshTokenFamilyRevocation.revokeFamily(${familyId}) failed (continuing tally):`,
				error,
			);
		}
	}

	try {
		await opts.federationTokenStore.deleteBySession(opts.sid);
	} catch (error) {
		stepTwoFailures.push(error);
		logger.warn(
			`cascadeLogout: federationTokenStore.deleteBySession(${opts.sid}) failed (continuing tally):`,
			error,
		);
	}

	if (stepTwoFailures.length > 0) {
		return { outcome: "failed", step: 2, errors: stepTwoFailures };
	}

	// §6.2 Step 3: reverse-index cleanup. Best-effort — log + continue, never
	// halt. Orphan reverse-index entries are bounded by TTL.
	await opts.sessionRPRegistry.removeBySid(opts.sid).catch((error) => {
		logger.warn(`cascadeLogout: sessionRPRegistry.removeBySid(${opts.sid}) failed:`, error);
	});
	await opts.sessionFamilyIndex.removeBySid(opts.sid).catch((error) => {
		logger.warn(`cascadeLogout: sessionFamilyIndex.removeBySid(${opts.sid}) failed:`, error);
	});
	await opts.sessionFederationIndex.removeBySid(opts.sid).catch((error) => {
		logger.warn(`cascadeLogout: sessionFederationIndex.removeBySid(${opts.sid}) failed:`, error);
	});

	// §6.2 Step 4: primary invalidation — must succeed.
	try {
		await opts.userSessionStore.delete(opts.sid);
	} catch (error) {
		return { outcome: "failed", step: 4, errors: [error] };
	}

	// CR-4 defense-in-depth: re-run sessionFamilyIndex cleanup AFTER the session
	// delete. The authorization grant's second-check (re-validate session before
	// addFamilyId) reduces but does not fully close the TOCTOU window — an
	// addFamilyId call interleaved between this Step 3 removeBySid and Step 4
	// delete leaves an orphan entry. This second pass clears it. Idempotent
	// (ZSET removal of a non-existent member is a no-op) and best-effort:
	// a failure here does not change the cascade outcome (orphan entries are
	// bounded by the family ZSET's TTL anyway).
	await opts.sessionFamilyIndex.removeBySid(opts.sid).catch((error) => {
		logger.warn(
			`cascadeLogout: post-delete sessionFamilyIndex.removeBySid(${opts.sid}) failed:`,
			error,
		);
	});

	return { outcome: "done" };
}
