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
 * The session lifecycle port's rules for a caller's input, as the Redis store
 * applies them before it writes: each a RangeError, nothing written. Every
 * rule is core's, read through the checks and limits core exports: a sid, a
 * sub and a participant id share the port's one rule for a key, which core's
 * participant check holds an id to, and a work item is a step name (core's
 * close-request check) or a participant's item.
 */
import { checkSessionCloseRequest, checkSessionParticipant, SESSION_LIFECYCLE_MAX_KEY_LENGTH, SESSION_LIFECYCLE_MAX_LISTING, SESSION_PARTICIPANT_KINDS, } from "@o3co/auth-provider-core";
/** `value` as the port's key: well-formed text of 1 to 512 UTF-16 code units. */
export function checkKey(value, name) {
    try {
        checkSessionParticipant({ kind: "rp", id: value, data: "" });
    }
    catch {
        throw new RangeError(`session lifecycle: ${name} must be 1 to ${SESSION_LIFECYCLE_MAX_KEY_LENGTH} characters of well-formed text`);
    }
    return value;
}
/** A participant the port admits, as core's frozen copy. */
export const checkParticipant = (participant) => checkSessionParticipant(participant);
/** A close request the port admits, as core's frozen copy. */
export const checkCloseRequest = (request) => checkSessionCloseRequest(request);
/** A session's end: a `Date` with a valid time, read from its own time value. */
export function checkExpiresAt(value) {
    let time = Number.NaN;
    try {
        if (value instanceof Date)
            time = Date.prototype.getTime.call(value);
    }
    catch {
        // Read as no valid time.
    }
    if (!Number.isFinite(time))
        throw new RangeError("session lifecycle: expiresAt must be a valid Date");
    return time;
}
/** A work item: a step name, or a participant's kind, a colon and its id. */
export function checkCloseItem(item) {
    const colon = typeof item === "string" ? item.indexOf(":") : -1;
    try {
        if (colon === -1) {
            checkSessionCloseRequest({ cause: "expiry", steps: [item], perParticipant: [], retainMs: 0 });
        }
        else {
            const kind = item.slice(0, colon);
            if (!SESSION_PARTICIPANT_KINDS.includes(kind))
                throw new Error(kind);
            checkSessionParticipant({
                kind: kind,
                id: item.slice(colon + 1),
                data: "",
            });
        }
    }
    catch {
        throw new RangeError("session lifecycle: item is no work item");
    }
    return item;
}
/** A listing's limit: a whole number from 1 to the port's most. */
export function checkListingLimit(limit) {
    if (!Number.isInteger(limit) || limit < 1 || limit > SESSION_LIFECYCLE_MAX_LISTING) {
        throw new RangeError(`session lifecycle: limit must be a whole number from 1 to ${SESSION_LIFECYCLE_MAX_LISTING}`);
    }
    return limit;
}
/** A listing's cursor: `""`, the start, or a key. */
export function checkListingCursor(after) {
    return after === "" ? after : checkKey(after, "after");
}
