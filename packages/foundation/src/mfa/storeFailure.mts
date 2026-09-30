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
 * unexpected version the subject and factor id through `auditErrorText` —
 * never from a body, a status text or a header the Store sent, and a body is
 * released unread. No `status`, `statusCode`, `expose` or `cause`: an HTTP
 * layer reading one would answer with the Store's status, and the client
 * gets the provider's generic answer for an outage, whatever went wrong.
 */

import { auditErrorText } from "@o3co/auth-provider-core";
import { endpointForMessage } from "../endpointUrl.mjs";

/** The Store's MFA endpoints, by what the provider asks of each. */
export type MfaStoreOperation = "list" | "create" | "update" | "delete" | "markMfaEnrolled";

/** Why an answer is not one the contract gives the operation. */
export type MfaStoreFailure =
	/** A status the contract does not give the operation. */
	| "unexpected_status"
	/** `markMfaEnrolled` answered `404`: the Store holds no such subject. */
	| "unknown_subject"
	/** A `2xx` whose body is not the contract's. */
	| "malformed_answer"
	/** A list holding a record the provider cannot read: the list is refused, never read as none. */
	| "unreadable_record"
	/** An update answered a version other than the expected one plus one. */
	| "version_skipped";

/** An MFA endpoint answered outside the contract. `name`, `reason`, `operation` and `storeStatus` are part of the contract. */
export class MfaStoreError extends Error {
	readonly reason: MfaStoreFailure;
	readonly operation: MfaStoreOperation;
	/** The Store's status, for a status the contract does not give the operation. */
	readonly storeStatus: number | undefined;

	constructor(
		message: string,
		reason: MfaStoreFailure,
		operation: MfaStoreOperation,
		storeStatus?: number,
	) {
		super(message);
		this.name = "MfaStoreError";
		this.reason = reason;
		this.operation = operation;
		this.storeStatus = storeStatus;
	}
}

const endpointOf = (operation: MfaStoreOperation, url: string): string =>
	`the Store's MFA ${operation} endpoint at ${endpointForMessage(url)}`;

/**
 * `response`'s status as an error, when the contract does not give it to
 * `operation`: `unknown_subject` for `markMfaEnrolled`'s `404`,
 * `unexpected_status` for any other. Reads the status alone and releases the
 * body without awaiting it, which a Store could otherwise hold open.
 */
export function mfaStoreStatusError(
	operation: MfaStoreOperation,
	url: string,
	response: Response,
): MfaStoreError {
	const status = response.status;
	response.body?.cancel().catch(() => {});
	if (operation === "markMfaEnrolled" && status === 404) {
		return new MfaStoreError(
			`${endpointOf(operation, url)} answered HTTP 404: it holds no such subject`,
			"unknown_subject",
			operation,
			status,
		);
	}
	return new MfaStoreError(
		`${endpointOf(operation, url)} answered HTTP ${status}`,
		"unexpected_status",
		operation,
		status,
	);
}

/** A `2xx` from `operation` whose body is not the contract's. */
export function mfaStoreMalformedAnswer(operation: MfaStoreOperation, url: string): MfaStoreError {
	return new MfaStoreError(
		`${endpointOf(operation, url)} answered a body that is not the contract's`,
		"malformed_answer",
		operation,
	);
}

/** A list holding a record the provider cannot read. */
export function mfaStoreUnreadableRecord(url: string): MfaStoreError {
	return new MfaStoreError(
		`${endpointOf("list", url)} answered a factor record the provider cannot read: the subject's factors are unavailable, never read as none`,
		"unreadable_record",
		"list",
	);
}

/** An update of `(subject, id)` at `expectedVersion` answered another version than `expectedVersion + 1`. */
export function mfaStoreVersionSkipped(
	url: string,
	update: { readonly subject: string; readonly id: string; readonly expectedVersion: number },
): MfaStoreError {
	return new MfaStoreError(
		`${endpointOf("update", url)} answered a version other than ${update.expectedVersion + 1} ` +
			`for subject ${auditErrorText(update.subject)}, factor ${auditErrorText(update.id)}`,
		"version_skipped",
		"update",
	);
}
