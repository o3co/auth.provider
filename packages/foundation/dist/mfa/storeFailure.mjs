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
 * What the Store adapter throws when an MFA endpoint answers outside the
 * contract (README, "The Store's MFA endpoints"). Transport failures, a
 * deadline and a refused credential are `StoreTransportError`,
 * `TimeoutError` and `StoreCredentialRefusedError`, as for the user
 * repository.
 *
 * Guarantees: an error is built from an allowlist — the operation, the
 * endpoint by origin and path, the Store's status as a number, and for an
 * unexpected version the subject and factor id through `auditErrorText`, at
 * most 64 characters each and ahead of the rest —
 * never from a body, a status text or a header the Store sent, and a body is
 * released unread. No `status`, `statusCode`, `expose` or `cause`: an HTTP
 * layer reading one would answer with the Store's status, and the client
 * gets the provider's generic answer for an outage, whatever went wrong.
 */
import { auditErrorText } from "@o3co/auth-provider-core";
import { endpointForMessage } from "../endpointUrl.mjs";
/** An MFA endpoint answered outside the contract. `name`, `reason`, `operation` and `storeStatus` are part of the contract. */
export class MfaStoreError extends Error {
    reason;
    operation;
    /** The Store's status, for a status the contract does not give the operation. */
    storeStatus;
    constructor(message, reason, operation, storeStatus) {
        super(message);
        this.name = "MfaStoreError";
        this.reason = reason;
        this.operation = operation;
        this.storeStatus = storeStatus;
    }
}
const endpointOf = (operation, url) => `the Store's MFA ${operation} endpoint at ${endpointForMessage(url)}`;
/**
 * What a transport failure of `operation` at `url` says, for the client
 * `owner` that sends it: one wording for every client of these endpoints,
 * naming the endpoint by origin and path.
 */
export function mfaStoreRequestMessages(owner, operation, url) {
    const endpoint = endpointOf(operation, url);
    return {
        owner,
        unreachable: `${owner}: ${endpoint} could not be reached`,
        closed: `${owner}: the connection to ${endpoint} closed before a complete response arrived`,
        malformed: `${owner}: ${endpoint} answered with a malformed HTTP response`,
        unreadable: `${owner}: the answer of ${endpoint} could not be read`,
    };
}
/**
 * `response`'s status as an error, when the contract does not give it to
 * `operation`: `unknown_subject` for `markMfaEnrolled`'s `404`,
 * `unexpected_status` for any other. Reads the status alone and releases the
 * body without awaiting it, which a Store could otherwise hold open.
 */
export function mfaStoreStatusError(operation, url, response) {
    const status = response.status;
    response.body?.cancel().catch(() => { });
    if (operation === "markMfaEnrolled" && status === 404) {
        return new MfaStoreError(`${endpointOf(operation, url)} answered HTTP 404: it holds no such subject`, "unknown_subject", operation, status);
    }
    return new MfaStoreError(`${endpointOf(operation, url)} answered HTTP ${status}`, "unexpected_status", operation, status);
}
/** A `2xx` from `operation` whose body is not the contract's. */
export function mfaStoreMalformedAnswer(operation, url) {
    return new MfaStoreError(`${endpointOf(operation, url)} answered a body that is not the contract's`, "malformed_answer", operation);
}
/** A list holding a record the provider cannot read. */
export function mfaStoreUnreadableRecord(url) {
    return new MfaStoreError(`${endpointOf("list", url)} answered a factor record the provider cannot read: the subject's factors are unavailable, never read as none`, "unreadable_record", "list");
}
/** The most characters of a subject or a factor id an error names. */
const IDENTIFIER_MAX_LENGTH = 64;
/**
 * `text` as an error names it: `auditErrorText`'s printable ASCII, cut at
 * {@link IDENTIFIER_MAX_LENGTH} with `...`.
 */
const identifier = (text) => {
    const safe = auditErrorText(text);
    return safe.length <= IDENTIFIER_MAX_LENGTH
        ? safe
        : `${safe.slice(0, IDENTIFIER_MAX_LENGTH - 3)}...`;
};
/**
 * An update of `(subject, id)` at `expectedVersion` answered another version
 * than `expectedVersion + 1`. The subject and the factor id lead the
 * message, so a log line that cuts it (`loggableError`, 256 characters) still
 * names both.
 */
export function mfaStoreVersionSkipped(url, update) {
    return new MfaStoreError(`subject ${identifier(update.subject)}, factor ${identifier(update.id)}: ` +
        `${endpointOf("update", url)} answered a version other than ${update.expectedVersion + 1}`, "version_skipped", "update");
}
