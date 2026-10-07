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
import { isObject, nonEmptyString } from "./input-values.mjs";
import { isIssuedAction, issuedActionsOf, } from "./requirement.mjs";
import { checkResolver } from "./requirement-resolver.mjs";
/** The claims `brandClaim` branded: the ones the claim builders made. */
const knownClaims = new WeakSet();
/**
 * What a code claim's builder read of the code: how its session had
 * authenticated at `/authorize`. Held beside the claim rather than on it, so
 * the claim's shape is the same for every carrier.
 */
const codeReadings = new WeakMap();
/**
 * Freezes and brands a claim a builder made, so `checkRequest` accepts it,
 * with what a code claim's builder read of the code. Called only by
 * `admit.mts`'s claim builders.
 */
export const brandClaim = (fields, codeReading) => {
    const built = Object.freeze({ ...fields });
    knownClaims.add(built);
    if (codeReading !== undefined)
        codeReadings.set(built, codeReading);
    return built;
};
const isStringList = (value) => Array.isArray(value) && value.every((entry) => typeof entry === "string" && entry.length > 0);
/**
 * A reader that reads `read` on its first call and answers that reading to
 * every later one. A read that throws is not kept.
 */
function readOnce(read) {
    let held;
    return () => {
        if (held === undefined)
            held = { value: read() };
        return held.value;
    };
}
/**
 * The action a request names: a registered action by its name — the object
 * registration made, so the grade is never the caller's to restate — or a
 * remediation core issued to one of these requirements, by its identity. Both
 * are core's vocabulary, so a log line names either. A remediation issued to
 * a requirement this resolver does not hold (another composition's, another
 * boot's) is refused as a literal or a copy is.
 */
function checkedAction(asked, requirements) {
    if (typeof asked === "string") {
        const registered = requirements.action(asked);
        if (registered === undefined) {
            throw new RangeError(`admitSession: ${JSON.stringify(asked)} is not a registered admission action: the module that admits it registers it under contributes.admissionActions`);
        }
        return registered;
    }
    // The issued object keeps its identity: step 5 lets it skip the requirements.
    if (isIssuedAction(asked) &&
        // Every registered copy was issued its actions ({} when it declared none).
        [...requirements.entries()].some(([, r]) => Object.values(issuedActionsOf(r)).includes(asked))) {
        return asked;
    }
    throw new RangeError("admitSession: the action is a registered action's name, or a remediation core issued to one of these requirements (issuedRemediationActions)");
}
/** A caller's fault is a `RangeError` before anything is read. Answers core's copy of what it read, each input read once, and the readers of the three stores and the audit sink. */
export function checkRequest(deps, request) {
    if (!isObject(deps))
        throw new RangeError("admitSession: deps must be an object");
    const requirements = checkResolver(deps.requirements);
    const acrTable = deps.acrTable;
    if (!isObject(acrTable))
        throw new RangeError("admitSession: acrTable must be an object");
    const logger = deps.logger;
    const configured = deps.now;
    const clock = configured === undefined ? () => new Date() : configured;
    const now = clock();
    if (!isObject(request))
        throw new RangeError("admitSession: the request must be an object");
    const presented = request.claim;
    if (!isObject(presented) || !knownClaims.has(presented)) {
        throw new RangeError("admitSession: the claim must be one a claim builder made — cookieClaim, codeClaimFirstRead, codeClaimRevalidation, linkClaim or tokenClaim");
    }
    // A branded claim is frozen and core's own; the copy is still taken, so
    // nothing downstream reads the caller's object twice.
    const claim = Object.freeze({
        authenticated: presented.authenticated === true,
        sid: nonEmptyString(presented.sid),
        subject: nonEmptyString(presented.subject),
        carrier: presented.carrier,
        ...(Array.isArray(presented.tokenAmr)
            ? { tokenAmr: Object.freeze([...presented.tokenAmr]) }
            : {}),
        ...(nonEmptyString(presented.renewalNonce) === undefined
            ? {}
            : { renewalNonce: presented.renewalNonce }),
    });
    const action = checkedAction(request.action, requirements);
    const asksRead = request.asks;
    let asks;
    if (asksRead !== undefined) {
        if (!isObject(asksRead))
            throw new RangeError("admitSession: asks must be an object");
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
        codeReading: codeReadings.get(presented),
        action,
        asks,
        requirements,
        readUserSessionStore: readOnce(() => deps.userSessionStore),
        readSubjectRevocation: readOnce(() => deps.subjectRevocation),
        readSessionLifecycleStore: readOnce(() => deps.sessionLifecycleStore),
        acrTable,
        logger,
        readAuditSink: readOnce(() => deps.auditSink),
        now,
        clock,
    };
}
