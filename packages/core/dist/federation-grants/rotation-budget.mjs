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
 * The rotation budget as a look reads it: at most `limit` upstream
 * refresh-token rotations per grant in a window of `windowMs`. The store's
 * `takeRotation` is what spends it, under the refresh lock; this reading is a
 * hint, by the same rule, that spares a spent budget the lock and the
 * upstream call. Pure: no clock, no store.
 *
 * A rotation here is a refresh the upstream may have acted on, whether or
 * not it issued a new refresh token.
 *
 * The window is fixed, not sliding: it opens at its first take and closes
 * `windowMs` later, so any `windowMs` that straddles two windows can hold up
 * to twice `limit`.
 */
import { instantOf } from "../federations/token-lifetime.mjs";
export const FEDERATION_GRANT_ROTATION_BUDGET_DEFAULTS = {
    limit: 24,
    windowMs: 3_600_000,
};
/** The budget the retrieval limits name, each part absent read as its default. */
export const federationGrantRotationBudget = (limits) => ({
    limit: limits.rotationBudget ?? FEDERATION_GRANT_ROTATION_BUDGET_DEFAULTS.limit,
    windowMs: limits.rotationWindowMs ?? FEDERATION_GRANT_ROTATION_BUDGET_DEFAULTS.windowMs,
});
/**
 * Whether a take at `nowMs` would be refused, by the store's rule: spent while
 * the window opened at `since` holds `limit` rotations and `nowMs` is before
 * `since + windowMs`. A `nowMs` behind `since` counts into the window. A `since`
 * that holds no instant is no window: the next take opens one.
 */
export function judgeFederationGrantRotationBudget(rotations, budget, nowMs) {
    if (rotations === undefined || rotations.count < budget.limit)
        return { spent: false };
    const closesAt = (instantOf(rotations.since) ?? Number.NaN) + budget.windowMs;
    if (!(nowMs < closesAt))
        return { spent: false };
    return { spent: true, retryAfterSeconds: Math.max(1, Math.ceil((closesAt - nowMs) / 1000)) };
}
