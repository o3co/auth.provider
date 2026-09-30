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
 * The template's guard that the requirement it declares for MFA is the
 * declared second-factor authority (`requireMfaSecondFactorAuthority`), on its
 * own: what it reads, what it refuses, and that it disposes the handle it was
 * given before refusing. The template's real path is pinned in
 * `session-requirements.test.mts`.
 */

import type { AppConfig, SessionRequirement } from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import {
	MfaRequirementNotAuthorityError,
	requireMfaSecondFactorAuthority,
} from "#/secondFactorAuthority.mjs";

const requirement = (over: Partial<SessionRequirement> = {}): SessionRequirement => ({
	name: "mfa",
	reach: new Set(),
	stepUpPage: undefined,
	remediations: [],
	hintKeys: [],
	admit: async () => ({ outcome: "met" }),
	...over,
});

/** A handle over `requirements`, recording whether it was disposed. */
const handleOver = (requirements: readonly SessionRequirement[] | undefined) => {
	const disposed: boolean[] = [];
	return {
		disposed,
		handle: {
			components:
				requirements === undefined
					? {}
					: { sessionRequirementResolver: resolverForTests(requirements) },
			dispose: async () => {
				disposed.push(true);
			},
		},
	};
};

const switches = (mode: string): AppConfig => ({ mfa: { mode } }) as unknown as AppConfig;

describe("requireMfaSecondFactorAuthority", () => {
	it("asks nothing under mfa.mode = off, whatever is registered", async () => {
		for (const requirements of [undefined, [], [requirement()]]) {
			const { handle, disposed } = handleOver(requirements);
			await requireMfaSecondFactorAuthority(switches("off"), handle);
			expect(disposed).toEqual([]);
		}
	});

	it.each(["optional", "required"] as const)(
		"passes under mfa.mode = %s when the requirement registered as mfa declares the second-factor authority",
		async (mode) => {
			const { handle, disposed } = handleOver([requirement({ secondFactorAuthority: true })]);
			await requireMfaSecondFactorAuthority(switches(mode), handle);
			expect(disposed).toEqual([]);
		},
	);

	it.each(["optional", "required"] as const)(
		"refuses under mfa.mode = %s, after disposing the handle, when the requirement registered as mfa does not declare the second-factor authority",
		async (mode) => {
			for (const declared of [undefined, false]) {
				const { handle, disposed } = handleOver([
					requirement(declared === undefined ? {} : { secondFactorAuthority: declared }),
				]);
				const err = await requireMfaSecondFactorAuthority(switches(mode), handle).then(
					() => undefined,
					(caught: unknown) => caught,
				);
				expect(err, String(declared)).toBeInstanceOf(MfaRequirementNotAuthorityError);
				expect((err as MfaRequirementNotAuthorityError).reason).toBe(
					"mfa-requirement-not-second-factor-authority",
				);
				expect((err as Error).message).toMatch(new RegExp(`mfa\\.mode is "${mode}"`));
				expect((err as Error).message).toMatch(/does not declare the second-factor authority/);
				expect(disposed, String(declared)).toEqual([true]);
			}
		},
	);

	it("refuses when nothing is registered as mfa, or no resolver was built: the second factor asked for has no authority", async () => {
		for (const requirements of [undefined, [], [requirement({ name: "other" })]]) {
			const { handle, disposed } = handleOver(requirements);
			await expect(
				requireMfaSecondFactorAuthority(switches("required"), handle),
			).rejects.toBeInstanceOf(MfaRequirementNotAuthorityError);
			expect(disposed).toEqual([true]);
		}
	});
});
