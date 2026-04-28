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
 * Discriminated reason union for ChallengeStorageError.
 * Per A1 §5.4 (lines 224-243).
 */
export type ChallengeStorageErrorReason = "duplicate" | "expired-at-issue";

/**
 * Single discriminated-reason error class for ChallengeStore + ReplaySeenSet
 * adapter primitives. Mirrors AdapterFactoryError / BootError discipline
 * (one class, discriminated reason, no per-reason subclasses).
 *
 * Per A1 §5.4. Throw matrix (A1 §5.4 lines 250-258):
 *   ChallengeStore.issue       — "duplicate" | "expired-at-issue"
 *   ChallengeStore.find        — (no throws)
 *   ChallengeStore.consume     — (no throws)
 *   ReplaySeenSet.markSeen     — "expired-at-issue"
 *   ReplaySeenSet.contains     — (no throws)
 *   ChallengeCeremony.consume  — (no throws in normal flow)
 */
export class ChallengeStorageError extends Error {
	readonly reason: ChallengeStorageErrorReason;

	constructor(opts: {
		reason: ChallengeStorageErrorReason;
		message?: string;
		cause?: unknown;
	}) {
		// Conditional super() argument so absent `cause` does not materialise an
		// own-property `cause` on the instance (matches Phase 4 BootError fix).
		if (opts.cause !== undefined) {
			super(opts.message ?? `ChallengeStorageError: ${opts.reason}`, { cause: opts.cause });
		} else {
			super(opts.message ?? `ChallengeStorageError: ${opts.reason}`);
		}
		this.name = "ChallengeStorageError";
		this.reason = opts.reason;
	}
}
