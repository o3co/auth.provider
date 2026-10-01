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
 * What a `DeviceCodeStore` records of an approval's authentication: the one
 * rule every store's `approve` applies, so all of them refuse and record the
 * same values.
 */

import { wellFormedAmr } from "../grants/authenticationClaims.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "../jwt/verify.mjs";
import type { ApproveDeviceAuthorizationInput } from "./types.mjs";

/** An approval's authentication as a store records it. Absent stays absent. */
export interface RecordableDeviceApproval {
	/** A frozen copy of the approving session's `amr`. */
	readonly amr: readonly string[] | undefined;
	/** When the approving session authenticated, in whole epoch milliseconds, never after the approval's clock. */
	readonly authTimeMs: number | undefined;
}

/**
 * The approval's `amr` and `authTime` as a store records them, each read
 * once. `nowMs` is the approval's clock: an instant up to
 * `DEFAULT_CLOCK_SKEW_MS` ahead of it is recorded as `nowMs` (a clock a
 * little ahead, which kept as it came would read as fresh for longer than it
 * is); one further ahead is no clock's reading. Every bundled store's
 * `approve` records this answer, never its own input.
 *
 * @throws RangeError for an `amr` that is not a non-empty list of non-empty
 *   strings, or an `authTime` that is not a valid `Date` at or after the
 *   epoch and no further ahead of `nowMs` than the skew. It quotes nothing of
 *   the value.
 */
export function recordableDeviceApproval(
	approval: Pick<ApproveDeviceAuthorizationInput, "amr" | "authTime">,
	nowMs: number,
): RecordableDeviceApproval {
	const amrGiven: unknown = approval.amr;
	const amr = amrGiven === undefined ? undefined : wellFormedAmr(amrGiven);
	if (amrGiven !== undefined && amr === undefined) {
		throw new RangeError(
			"DeviceCodeStore.approve: amr must be a non-empty list of non-empty strings",
		);
	}
	const authTime: unknown = approval.authTime;
	const ms = authTime instanceof Date ? authTime.getTime() : Number.NaN;
	if (authTime !== undefined && !(ms >= 0 && ms <= nowMs + DEFAULT_CLOCK_SKEW_MS)) {
		throw new RangeError(
			"DeviceCodeStore.approve: authTime must be a valid Date at or after the epoch, no further ahead of the approval than the clock skew",
		);
	}
	return {
		amr: amr === undefined ? undefined : Object.freeze(amr),
		// A Date's milliseconds are whole; the clock's may not be.
		authTimeMs: authTime === undefined ? undefined : Math.min(ms, Math.floor(nowMs)),
	};
}
