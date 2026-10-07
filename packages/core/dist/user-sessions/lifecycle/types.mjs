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
/** A session's states, in the only order it moves through them. */
export const SESSION_LIFECYCLE_STATES = Object.freeze(["active", "closing", "closed"]);
/** What may join a session: a relying party, a refresh-token family, an upstream federation. */
export const SESSION_PARTICIPANT_KINDS = Object.freeze(["rp", "family", "federation"]);
/** Why a session is closed. The first close's cause is the one kept. */
export const SESSION_CLOSE_CAUSES = Object.freeze([
    "rp_logout",
    "session_logout",
    "subject_revocation",
    "operator_reset",
    "expiry",
]);
/**
 * The longest sid, sub or participant id, in UTF-16 code units (`length`).
 * Each is well-formed text, no lone surrogate, so its UTF-8 bytes name it
 * alone.
 */
export const SESSION_LIFECYCLE_MAX_KEY_LENGTH = 512;
/** The longest participant `data`, in UTF-16 code units (`length`). */
export const SESSION_PARTICIPANT_MAX_DATA_LENGTH = 8192;
/** The most sids one `listClosing` may ask for. */
export const SESSION_LIFECYCLE_MAX_LISTING = 1000;
/** The work item one participant makes: its kind, a colon, its id. No step name holds a colon. */
export function sessionCloseItemOf(participant) {
    return `${participant.kind}:${participant.id}`;
}
