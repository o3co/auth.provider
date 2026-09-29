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
 * The one bound on an MFA record's version (the MFA ADR's D7, D8): the
 * compare-and-set token both stores, `MfaFactorStore` and
 * `MfaTransactionStore`, bump by one on every update. A record may be created
 * at any safe non-negative version, and the update from
 * `Number.MAX_SAFE_INTEGER` is the one that cannot advance: its next version
 * is no safe integer — a store would write 2^53, which a read refuses, or
 * keep a version that no longer moves, so two writers would both win.
 */

/**
 * Refuses, with a `RangeError` naming `operation`, an update at
 * `expectedVersion` whose next version would not be a safe integer —
 * `Number.MAX_SAFE_INTEGER` — before anything is read or written, whatever
 * the stored version, as a value a field does not admit is refused. Every
 * other value passes: one no record can be at is the store's `null`.
 */
export function checkMfaVersionAdvances(expectedVersion: number, operation: string): void {
	if (expectedVersion === Number.MAX_SAFE_INTEGER) {
		throw new RangeError(
			`${operation}: a record at version Number.MAX_SAFE_INTEGER cannot be updated — its next version would be no safe integer`,
		);
	}
}
