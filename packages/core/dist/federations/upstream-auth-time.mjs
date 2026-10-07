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
import { DEFAULT_CLOCK_SKEW_MS } from "../jwt/verify.mjs";
/**
 * A verified id_token's `auth_time` as an instant: `undefined` when the claim
 * is absent; its whole seconds since the epoch, a fraction floored — OIDC
 * allows one, and flooring never answers an instant later than the claim;
 * `"invalid"` for a value that is not a finite number, is negative, or lies
 * more than `aheadToleranceMs` (default `DEFAULT_CLOCK_SKEW_MS`) ahead of
 * `nowMs`, which would read as fresher than any ask. An adapter whose library
 * tolerates more clock skew passes its own tolerance. An adapter fails the
 * login on `"invalid"`. Throws a `RangeError` only for a clock that is not a
 * finite number or a tolerance that is not a finite duration ≥ 0.
 */
export function readUpstreamAuthTime(claim, nowMs = Date.now(), aheadToleranceMs = DEFAULT_CLOCK_SKEW_MS) {
    if (!Number.isFinite(nowMs))
        throw new RangeError("nowMs must be a finite epoch ms");
    if (!Number.isFinite(aheadToleranceMs) || aheadToleranceMs < 0) {
        throw new RangeError("aheadToleranceMs must be a finite number of ms, at least 0");
    }
    if (claim === undefined)
        return undefined;
    if (typeof claim !== "number" || !Number.isFinite(claim) || claim < 0)
        return "invalid";
    const instantMs = Math.floor(claim) * 1000;
    return instantMs <= nowMs + aheadToleranceMs ? new Date(instantMs) : "invalid";
}
