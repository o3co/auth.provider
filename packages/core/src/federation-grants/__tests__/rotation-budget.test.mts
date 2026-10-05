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

import { describe, expect, it } from "vitest";
import {
	FEDERATION_GRANT_ROTATION_BUDGET_DEFAULTS,
	federationGrantRotationBudget,
	judgeFederationGrantRotationBudget,
} from "#/federation-grants/rotation-budget.mjs";

const T0 = new Date("2026-09-18T00:00:00.000Z").getTime();
const HOUR = 3_600_000;
const budget = { limit: 3, windowMs: HOUR };

describe("federationGrantRotationBudget", () => {
	it("is 24 rotations an hour when the limits name none", () => {
		expect(FEDERATION_GRANT_ROTATION_BUDGET_DEFAULTS).toEqual({ limit: 24, windowMs: HOUR });
		expect(federationGrantRotationBudget({})).toEqual({ limit: 24, windowMs: HOUR });
	});

	it("is what the limits name", () => {
		expect(federationGrantRotationBudget({ rotationBudget: 5, rotationWindowMs: 60_000 })).toEqual({
			limit: 5,
			windowMs: 60_000,
		});
	});
});

describe("judgeFederationGrantRotationBudget — the store's rule, read as a hint", () => {
	it("is not spent for a grant that never took a rotation", () => {
		expect(judgeFederationGrantRotationBudget(undefined, budget, T0)).toEqual({ spent: false });
	});

	it("is not spent while the window holds fewer than the limit", () => {
		const rotations = { since: new Date(T0), count: 2 };
		expect(judgeFederationGrantRotationBudget(rotations, budget, T0 + 10 * 60_000)).toEqual({
			spent: false,
		});
	});

	it("is spent at the limit, until the window that opened at `since` closes", () => {
		const rotations = { since: new Date(T0), count: 3 };
		expect(judgeFederationGrantRotationBudget(rotations, budget, T0 + 10 * 60_000)).toEqual({
			spent: true,
			retryAfterSeconds: 50 * 60,
		});
		expect(judgeFederationGrantRotationBudget(rotations, budget, T0 + HOUR - 1)).toEqual({
			spent: true,
			retryAfterSeconds: 1,
		});
		// The store opens a new window at `since + windowMs`, not after it.
		expect(judgeFederationGrantRotationBudget(rotations, budget, T0 + HOUR)).toEqual({
			spent: false,
		});
	});

	it("rounds the wait up to whole seconds: a client told to come back early is refused again", () => {
		const rotations = { since: new Date(T0), count: 3 };
		expect(judgeFederationGrantRotationBudget(rotations, budget, T0 + HOUR - 1_500)).toEqual({
			spent: true,
			retryAfterSeconds: 2,
		});
	});

	it("counts a `now` behind `since` into the window, as the store does: an earlier clock fails closed", () => {
		const rotations = { since: new Date(T0), count: 3 };
		expect(judgeFederationGrantRotationBudget(rotations, budget, T0 - 60_000)).toEqual({
			spent: true,
			retryAfterSeconds: 61 * 60,
		});
	});

	it("reads a window whose start holds no instant as no window: the next take opens one", () => {
		// Denying for ever on a date nobody can read would starve the grant.
		const rotations = { since: new Date(Number.NaN), count: 3 };
		expect(judgeFederationGrantRotationBudget(rotations, budget, T0)).toEqual({ spent: false });
	});
});
