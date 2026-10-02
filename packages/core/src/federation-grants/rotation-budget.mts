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
 * The window is fixed, not sliding: it opens at its first take and closes
 * `windowMs` later, so any `windowMs` that straddles two windows can hold up
 * to twice `limit`.
 */

import { instantOf } from "../federations/token-lifetime.mjs";
import type { FederationGrantRotations } from "./types.mjs";

export interface FederationGrantRotationBudget {
	/** Rotations a window admits: a whole number of at least one. */
	readonly limit: number;
	readonly windowMs: number;
}

export const FEDERATION_GRANT_ROTATION_BUDGET_DEFAULTS: FederationGrantRotationBudget = {
	limit: 24,
	windowMs: 3_600_000,
};

/** The budget the retrieval limits name, each part absent read as its default. */
export const federationGrantRotationBudget = (limits: {
	readonly rotationBudget?: number;
	readonly rotationWindowMs?: number;
}): FederationGrantRotationBudget => ({
	limit: limits.rotationBudget ?? FEDERATION_GRANT_ROTATION_BUDGET_DEFAULTS.limit,
	windowMs: limits.rotationWindowMs ?? FEDERATION_GRANT_ROTATION_BUDGET_DEFAULTS.windowMs,
});

export type FederationGrantRotationBudgetJudgement =
	| { readonly spent: false }
	/** `retryAfterSeconds`: until the window closes, whole seconds rounded up, at least one. */
	| { readonly spent: true; readonly retryAfterSeconds: number };

/**
 * Whether a take at `nowMs` would be refused, by the store's rule: spent while
 * the window opened at `since` holds `limit` rotations and `nowMs` is before
 * `since + windowMs`. A `nowMs` behind `since` counts into the window. A `since`
 * that holds no instant is no window: the next take opens one.
 */
export function judgeFederationGrantRotationBudget(
	rotations: FederationGrantRotations | undefined,
	budget: FederationGrantRotationBudget,
	nowMs: number,
): FederationGrantRotationBudgetJudgement {
	if (rotations === undefined || rotations.count < budget.limit) return { spent: false };
	const closesAt = (instantOf(rotations.since) ?? Number.NaN) + budget.windowMs;
	if (!(nowMs < closesAt)) return { spent: false };
	return { spent: true, retryAfterSeconds: Math.max(1, Math.ceil((closesAt - nowMs) / 1000)) };
}
