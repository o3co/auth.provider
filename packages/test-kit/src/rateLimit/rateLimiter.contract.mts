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
 * The contract suite of the `RateLimiter` port, the `rateLimiter` slot's
 * value.
 *
 * `rateLimiterContract(input)` holds a limiter to what the rate-limit guard
 * relies on: a `kind` that names it; a `failMode` (its own outage policy),
 * if declared, of the guard's two; a well-formed decision; with
 * `withOutage`, an outage thrown, never answered as a decision, so the
 * guard's policy and report apply; with `withBudget`, a key allowed its
 * limit and refused past it, each key counted apart, a key under a prefix
 * named after an `Object.prototype` member included. The budget case hands
 * one spec for every key: how a limiter resolves a spec is its own.
 *
 * The port's test double, `createTestRateLimiter`, is core's, on its testing
 * entry.
 */

import assert from "node:assert/strict";
import {
	isUsableRateLimitSpec,
	type RateLimitContext,
	type RateLimitDecision,
	type RateLimiter,
	type RateLimitFailMode,
	type RateLimitSpec,
} from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";

export interface RateLimiterContractInput {
	/** A fresh limiter for each case, over a backend that answers. */
	readonly build: () => RateLimiter;
	/** The limiter over a backend that is down: `check` must reject. Absent for a limiter with no backend of its own. */
	readonly withOutage?: () => RateLimiter;
	/** The limiter applying `spec` to every key. Absent for a limiter that takes no spec. */
	readonly withBudget?: (spec: RateLimitSpec) => RateLimiter;
}

const FAIL_MODES: ReadonlySet<unknown> = new Set<RateLimitFailMode>(["open", "closed"]);
const CONTEXT: RateLimitContext = { ip: "192.0.2.1" };

/** Prefixes the budget case spends under: an ordinary one, and names a plain object inherits. */
const BUDGET_PREFIXES = ["contract", "constructor", "__proto__", "toString", "valueOf"] as const;

const wholeFrom = (value: unknown, least: number): boolean =>
	typeof value === "number" && Number.isInteger(value) && value >= least;

/** Throws unless `decision` is one the guard can read. */
function checkDecision(decision: unknown): void {
	assert.ok(
		typeof decision === "object" && decision !== null,
		`check answered ${String(decision)}, not a decision`,
	);
	const { allowed, remaining, limit, resetAt, reason } = decision as Record<string, unknown>;
	assert.equal(typeof allowed, "boolean", `allowed ${String(allowed)} is not true or false`);
	if (remaining !== undefined) {
		assert.ok(
			wholeFrom(remaining, 0),
			`remaining ${String(remaining)} is not a whole number from 0`,
		);
	}
	if (limit !== undefined) {
		assert.ok(wholeFrom(limit, 1), `limit ${String(limit)} is not a whole number from 1`);
	}
	if (resetAt !== undefined) {
		assert.ok(
			resetAt instanceof Date && !Number.isNaN(resetAt.getTime()),
			`resetAt ${String(resetAt)} is not a valid Date`,
		);
	}
	if (reason !== undefined) {
		assert.equal(typeof reason, "string", `reason ${String(reason)} is not a string`);
	}
}

/** The cases of the `RateLimiter` contract over the limiters `input` builds. */
export function rateLimiterContract(input: RateLimiterContractInput): readonly ContractCase[] {
	const { build, withOutage, withBudget } = input;
	const cases: ContractCase[] = [
		{
			name: "kind is a non-empty string",
			run: async () => {
				const { kind } = build();
				assert.ok(
					typeof kind === "string" && kind.length > 0,
					`kind ${String(kind)} names nothing`,
				);
			},
		},
		{
			name: "failMode, when present, is open or closed",
			run: async () => {
				const limiter = build();
				if (!("failMode" in limiter) || limiter.failMode === undefined) return;
				assert.ok(
					FAIL_MODES.has(limiter.failMode),
					`failMode ${JSON.stringify(limiter.failMode)} is not "open" or "closed"`,
				);
			},
		},
		{
			name: "defaultLimit, when present, is a budget a limiter can apply as written",
			run: async () => {
				const limiter = build();
				if (!("defaultLimit" in limiter) || limiter.defaultLimit === undefined) return;
				assert.ok(
					isUsableRateLimitSpec(limiter.defaultLimit),
					`defaultLimit ${JSON.stringify(limiter.defaultLimit)} is not a usable { limit, windowSeconds }`,
				);
			},
		},
		{
			name: "check answers a decision: allowed true or false, and remaining, limit, resetAt and reason well-formed when present",
			run: async () => {
				checkDecision(await build().check("contract:ip:192.0.2.1", CONTEXT));
			},
		},
	];
	if (withOutage !== undefined) {
		cases.push({
			name: "an outage is thrown, never answered as a decision",
			run: async () => {
				await assert.rejects(
					withOutage().check("contract:ip:192.0.2.1", CONTEXT),
					"a limiter whose backend is down must throw, so the guard applies its policy and reports the outage",
				);
			},
		});
	}
	if (withBudget !== undefined) {
		cases.push({
			name: "a key is allowed its limit and refused past it, under a prefix named after an Object.prototype member too, and another key is counted apart",
			run: async () => {
				const limiter = withBudget({ limit: 2, windowSeconds: 60 });
				for (const prefix of BUDGET_PREFIXES) {
					const spent = `${prefix}:ip:192.0.2.1`;
					const answers: RateLimitDecision[] = [];
					for (let i = 0; i < 3; i++) answers.push(await limiter.check(spent, CONTEXT));
					for (const answer of answers) checkDecision(answer);
					assert.deepEqual(
						answers.map((a) => a.allowed),
						[true, true, false],
						`a limit of 2 must allow ${spent} twice and refuse it the third time`,
					);
				}
				const other = await limiter.check("contract:ip:192.0.2.2", { ip: "192.0.2.2" });
				assert.equal(other.allowed, true, "another key was refused for the first key's checks");
			},
		});
	}
	return cases;
}
