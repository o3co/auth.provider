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
 * Reasons emitted by `RefreshTokenStorageError`.
 *
 * - `duplicate-family`: registerFamily called for an existing familyId
 *   (RNG collision or programming bug; surfaces loudly).
 * - `expired-at-issue`: register/issue path detected `expiresAt <= now()`
 *   at call time; the storage layer fails closed.
 * - `conflict-exhausted`: updateFamily's CAS retry budget exhausted under
 *   sustained contention; load-shedding signal.
 *
 * Per A3 §5.4.
 */
export type RefreshTokenStorageErrorReason =
	| "duplicate-family"
	| "expired-at-issue"
	| "conflict-exhausted";

/**
 * Single error class for `RefreshTokenFamilyStore` domain failures.
 * Mirrors A1's `ChallengeStorageError` shape: discriminated `reason` field,
 * native ES2022 `cause` for chaining underlying adapter errors, default
 * message templated from `reason`.
 *
 * Per A3 §5.4.
 */
export class RefreshTokenStorageError extends Error {
	readonly reason: RefreshTokenStorageErrorReason;

	constructor(opts: {
		reason: RefreshTokenStorageErrorReason;
		message?: string;
		cause?: unknown;
	}) {
		super(
			opts.message ?? `RefreshTokenStorageError: ${opts.reason}`,
			opts.cause !== undefined ? { cause: opts.cause } : undefined,
		);
		this.name = "RefreshTokenStorageError";
		this.reason = opts.reason;
	}
}
