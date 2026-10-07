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
/** Every status each outcome type admits: `satisfies` fails the build when the type gains or loses one. */
const POLL_STATUSES = {
    not_found: true,
    expired: true,
    denied: true,
    pending: true,
    slow_down: true,
    approved: true,
};
const DECISION_STATUSES = {
    ok: true,
    not_found: true,
    expired: true,
    already_decided: true,
};
const UNREADABLE = Symbol("unreadable");
/** `source[field]`, read once, or `UNREADABLE` for a read that throws. */
const fieldOf = (source, field) => {
    try {
        return source[field];
    }
    catch {
        return UNREADABLE;
    }
};
const malformed = (field) => ({
    ok: false,
    refused: "outcome_malformed",
    field,
});
const NOT_AN_OBJECT = { ok: false, refused: "outcome_not_an_object" };
/** `outcome`'s `status`, read once, if it is one `statuses` holds. */
const statusOf = (outcome, statuses) => {
    const status = fieldOf(outcome, "status");
    return typeof status === "string" && Object.hasOwn(statuses, status) ? status : undefined;
};
/**
 * A `poll` answer read once. A `slow_down` interval is held to the rule
 * `readDeviceAuthorization` holds a record's interval to: a finite number of
 * seconds, zero or more.
 */
export function readPollOutcome(outcome) {
    if (typeof outcome !== "object" || outcome === null)
        return NOT_AN_OBJECT;
    const status = statusOf(outcome, POLL_STATUSES);
    switch (status) {
        case undefined:
            return malformed("status");
        case "slow_down": {
            const intervalSeconds = fieldOf(outcome, "intervalSeconds");
            return typeof intervalSeconds === "number" &&
                Number.isFinite(intervalSeconds) &&
                intervalSeconds >= 0
                ? { ok: true, answer: { status, intervalSeconds } }
                : malformed("intervalSeconds");
        }
        case "approved":
            return { ok: true, answer: { status, authorization: fieldOf(outcome, "authorization") } };
        default:
            return { ok: true, answer: { status } };
    }
}
/**
 * An `approve` or `deny` answer read once. An `already_decided` holds a
 * decision: `approved` or `denied`, never `pending`.
 */
export function readDecisionOutcome(outcome) {
    if (typeof outcome !== "object" || outcome === null)
        return NOT_AN_OBJECT;
    const status = statusOf(outcome, DECISION_STATUSES);
    switch (status) {
        case undefined:
            return malformed("status");
        case "already_decided": {
            const current = fieldOf(outcome, "current");
            return current === "approved" || current === "denied"
                ? { ok: true, answer: { status, current } }
                : malformed("current");
        }
        case "ok":
            return { ok: true, answer: { status, authorization: fieldOf(outcome, "authorization") } };
        default:
            return { ok: true, answer: { status } };
    }
}
