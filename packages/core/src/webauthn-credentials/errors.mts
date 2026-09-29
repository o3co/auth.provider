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
 * Reasons emitted by `WebAuthnCredentialStorageError`.
 *
 * - `duplicate-credential`: `registerCredential` for a `credentialId` that
 *   already exists. The insert is rejected and the existing record kept, so
 *   callers can answer the registering client 400 rather than silently
 *   overwrite (TOCTOU prevention).
 */
export type WebAuthnCredentialStorageErrorReason = "duplicate-credential";

/**
 * The error of `WebAuthnCredentialStore` adapter primitives, shaped like
 * `RefreshTokenStorageError` and `ChallengeStorageError`: a discriminated
 * `reason`, native `cause` for the adapter's error, and a default message
 * templated from `reason`.
 */
export class WebAuthnCredentialStorageError extends Error {
	readonly reason: WebAuthnCredentialStorageErrorReason;

	constructor(opts: {
		reason: WebAuthnCredentialStorageErrorReason;
		message?: string;
		cause?: unknown;
	}) {
		super(
			opts.message ?? `WebAuthnCredentialStorageError: ${opts.reason}`,
			opts.cause !== undefined ? { cause: opts.cause } : undefined,
		);
		this.name = "WebAuthnCredentialStorageError";
		this.reason = opts.reason;
	}
}
