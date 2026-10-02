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
 * What admission accepts as a request, checked before anything is read: a
 * claim one of the builders branded here (a module-private `WeakSet`), the
 * action by its registration or its issued identity, and well-formed asks.
 * A caller's fault is a `RangeError`; every input is read once and copied,
 * except the session store, the revocation boundary and the audit sink,
 * which `readLiveSession` reads off `deps` once each in the step that uses
 * it: a store's read that throws is its outage, the sink's a failed audit.
 */

import type { AuditSink } from "../audit/types.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { SubjectRevocation, UserSessionStore } from "../user-sessions/types.mjs";
import type { AcrTable } from "./acr.mjs";
import type { AdmissionAction } from "./actions.mjs";
import { isObject, nonEmptyString } from "./input-values.mjs";
import {
	type AdmissionAsks,
	type AdmissionDeps,
	type AdmissionRequest,
	isIssuedAction,
	type SessionClaim,
	type SessionRequirementResolver,
} from "./requirement.mjs";
import { checkResolver } from "./requirement-resolver.mjs";

/** The claims `brandClaim` branded: the ones the claim builders made. */
const knownClaims = new WeakSet<object>();

/**
 * Freezes and brands a claim a builder made, so `checkRequest` accepts it.
 * Called only by `admit.mts`'s claim builders.
 */
export const brandClaim = (fields: Omit<SessionClaim, never>): SessionClaim => {
	const built = Object.freeze({ ...fields });
	knownClaims.add(built);
	return built;
};

const isStringList = (value: unknown): value is readonly string[] =>
	Array.isArray(value) && value.every((entry) => typeof entry === "string" && entry.length > 0);

/**
 * What `checkRequest` answers: every untrusted input (claim, action, `asks`,
 * each other dependency off `deps`) read once and copied, so a getter
 * answering one thing to the check and another to the steps changes
 * nothing, and a requirement cannot reach the caller's objects. The session
 * store, the revocation boundary and the audit sink are not read here:
 * `readLiveSession` calls each reader once, in the guarded step that uses
 * it, so a read that throws never escapes admission — a store's is
 * `unavailable`, the sink's fails as the audit it was read for.
 */
export interface CheckedRequest {
	readonly claim: SessionClaim;
	readonly action: AdmissionAction;
	readonly asks: AdmissionAsks | undefined;
	readonly requirements: SessionRequirementResolver;
	readonly readUserSessionStore: () => UserSessionStore | undefined;
	readonly readSubjectRevocation: () => SubjectRevocation | undefined;
	readonly acrTable: AcrTable;
	readonly logger: Logger | undefined;
	readonly readAuditSink: () => AuditSink | undefined;
	readonly now: Date;
}

/**
 * The action a request names: a registered action by its name — the object
 * registration made, so the grade is never the caller's to restate — or a
 * remediation core issued to a requirement, by its identity. Both are core's
 * vocabulary, so a log line names either.
 */
function checkedAction(asked: unknown, requirements: SessionRequirementResolver): AdmissionAction {
	if (typeof asked === "string") {
		const registered = requirements.action(asked);
		if (registered === undefined) {
			throw new RangeError(
				`admitSession: ${JSON.stringify(asked)} is not a registered admission action: the module that admits it registers it under contributes.admissionActions`,
			);
		}
		return registered;
	}
	// The issued object keeps its identity: that is what step 5 checks.
	if (isIssuedAction(asked)) return asked;
	throw new RangeError(
		"admitSession: the action is a registered action's name, or a remediation core issued to a requirement (issuedRemediationActions)",
	);
}

/** A caller's fault is a `RangeError` before anything is read. Answers core's copy of what it read, each input read once, and the readers of the two stores and the audit sink. */
export function checkRequest(deps: AdmissionDeps, request: AdmissionRequest): CheckedRequest {
	if (!isObject(deps)) throw new RangeError("admitSession: deps must be an object");
	const requirements = checkResolver(deps.requirements);
	const acrTable = deps.acrTable;
	if (!isObject(acrTable)) throw new RangeError("admitSession: acrTable must be an object");
	const logger = deps.logger;
	const clock = deps.now;
	const now = clock === undefined ? new Date() : clock();
	if (!isObject(request)) throw new RangeError("admitSession: the request must be an object");
	const presented = request.claim;
	if (!isObject(presented) || !knownClaims.has(presented)) {
		throw new RangeError(
			"admitSession: the claim must be one a claim builder made — cookieClaim, codeClaimFirstRead, codeClaimRevalidation, linkClaim or tokenClaim",
		);
	}
	// A branded claim is frozen and core's own; the copy is still taken, so
	// nothing downstream reads the caller's object twice.
	const claim = Object.freeze({
		authenticated: presented.authenticated === true,
		sid: nonEmptyString(presented.sid),
		subject: nonEmptyString(presented.subject),
		carrier: presented.carrier,
		...(Array.isArray(presented.tokenAmr)
			? { tokenAmr: Object.freeze([...(presented.tokenAmr as readonly string[])]) }
			: {}),
		...(nonEmptyString(presented.renewalNonce) === undefined
			? {}
			: { renewalNonce: presented.renewalNonce }),
	}) as SessionClaim;
	const action = checkedAction(request.action, requirements);
	const asksRead = request.asks;
	let asks: AdmissionAsks | undefined;
	if (asksRead !== undefined) {
		if (!isObject(asksRead)) throw new RangeError("admitSession: asks must be an object");
		const acrValues = asksRead.acrValues;
		if (acrValues !== undefined && !isStringList(acrValues)) {
			throw new RangeError("admitSession: asks.acrValues must be a list of non-empty strings");
		}
		asks = Object.freeze({
			...(acrValues === undefined ? {} : { acrValues: Object.freeze([...acrValues]) }),
		});
	}
	return {
		claim,
		action,
		asks,
		requirements,
		readUserSessionStore: () => deps.userSessionStore,
		readSubjectRevocation: () => deps.subjectRevocation,
		acrTable,
		logger,
		readAuditSink: () => deps.auditSink,
		now,
	};
}
