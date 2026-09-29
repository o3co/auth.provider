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

/** Discriminated reason union for ChallengeStorageError. */
export type ChallengeStorageErrorReason = "duplicate" | "expired-at-issue";

/**
 * The one error class for ChallengeStore and ReplaySeenSet adapter
 * primitives, discriminated by `reason` like AdapterFactoryError and
 * BootError. Only `ChallengeStore.issue` (`duplicate`, `expired-at-issue`)
 * and `ReplaySeenSet.markSeen` (`expired-at-issue`) throw it. An expiry
 * outside the Date range is a RangeError instead: a caller fault, not to be
 * mistaken for the `expired-at-issue` race the ceremony swallows.
 */
export class ChallengeStorageError extends Error {
	readonly reason: ChallengeStorageErrorReason;

	constructor(opts: {
		reason: ChallengeStorageErrorReason;
		message?: string;
		cause?: unknown;
	}) {
		// Conditional super-arg so an absent `cause` does not materialise an
		// own-property `cause` on the instance; the same idiom as BootError.
		super(
			opts.message ?? `ChallengeStorageError: ${opts.reason}`,
			opts.cause !== undefined ? { cause: opts.cause } : undefined,
		);
		this.name = "ChallengeStorageError";
		this.reason = opts.reason;
	}
}
