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
 * The stage-1 check registry (#368).
 *
 * validate-manifests had accreted hand-numbered fractional steps (7.5,
 * 13.5–13.10) threaded into `validateManifests` inside nested blocks —
 * adding a wiring guard meant choosing a fraction and finding the right
 * brace. The checks are now two ordered registries (pre-config and
 * post-config, split by the config-parse stage that produces the value the
 * post-config guards read), and adding a guard is appending a row.
 *
 * Behavior is pinned elsewhere: validate-manifests.test.mts and the
 * per-guard suites assert every check's semantics and first-violation
 * ordering. This suite pins the registry's own shape.
 */
import { describe, expect, it } from "vitest";
import {
	STAGE_ONE_POST_CONFIG_CHECKS,
	STAGE_ONE_PRE_CONFIG_CHECKS,
} from "#/boot/validate-manifests.mjs";

describe("stage-1 check registries (#368)", () => {
	const all = [...STAGE_ONE_PRE_CONFIG_CHECKS, ...STAGE_ONE_POST_CONFIG_CHECKS];

	it("gives every check a unique id", () => {
		const ids = all.map((check) => check.id);
		expect(new Set(ids).size).toBe(ids.length);
	});

	it("gives every check a spec reference, so a row cannot lose its provenance", () => {
		for (const check of all) {
			expect(check.spec, check.id).toMatch(/A2-β|issue #\d+|A5 |CP-\d+/);
		}
	});

	it("keeps the documented order — the spec steps run in spec order, guards after config parse", () => {
		expect(STAGE_ONE_PRE_CONFIG_CHECKS.map((c) => c.id)).toEqual([
			"unique-module-names",
			"provides-closure",
			"bootstrap-synthetic-disjointness",
			"requires-closure",
			"contribution-kind-coverage",
			"per-kind-contribute-duplicates",
			"route-collisions",
			"federation-redirect-policy-pairing",
			"override-targets",
			"override-duplicates",
			"same-module-contribute-override",
			"list-shaped-overrides",
			"lifecycle-closure",
		]);
		expect(STAGE_ONE_POST_CONFIG_CHECKS.map((c) => c.id)).toEqual([
			"grant-policy-issuer",
			"mfa-partial-wiring",
			"federation-stores-wiring",
			"declared-absence",
			"replica-safety",
			"route-order-edges",
		]);
	});

	it("is frozen, rows included — the execution plan is not mutable in-process", () => {
		expect(Object.isFrozen(STAGE_ONE_PRE_CONFIG_CHECKS)).toBe(true);
		expect(Object.isFrozen(STAGE_ONE_POST_CONFIG_CHECKS)).toBe(true);
		for (const check of all) {
			expect(Object.isFrozen(check), check.id).toBe(true);
		}
	});
});
