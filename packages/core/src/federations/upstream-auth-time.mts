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

/*
 * The one reading of an upstream id_token's `auth_time` claim (OIDC Core §2),
 * which every adapter answers `FederationProfile.authTime` with. Pure apart
 * from the default clock.
 */

import { isWholeEpochSeconds } from "../jwt/numericDate.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "../jwt/verify.mjs";

/**
 * A verified id_token's `auth_time` as an instant: `undefined` when the claim
 * is absent; `"invalid"` when it is not whole seconds since the epoch, or lies
 * more than `DEFAULT_CLOCK_SKEW_MS` ahead of `nowMs`, which would read as
 * fresher than any ask. An adapter fails the login on `"invalid"`. Throws a
 * `RangeError` only for a clock that is not a finite number.
 */
export function readUpstreamAuthTime(
	claim: unknown,
	nowMs: number = Date.now(),
): Date | undefined | "invalid" {
	if (!Number.isFinite(nowMs)) throw new RangeError("nowMs must be a finite epoch ms");
	if (claim === undefined) return undefined;
	if (!isWholeEpochSeconds(claim)) return "invalid";
	const instantMs = claim * 1000;
	return instantMs <= nowMs + DEFAULT_CLOCK_SKEW_MS ? new Date(instantMs) : "invalid";
}
