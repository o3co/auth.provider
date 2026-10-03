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
 * Every section this package's modules read refuses a key it does not know,
 * at every object level: core's `sectionStrictnessProblems` over the
 * package's `reference.conf`, and boot, which names the key at its path. A
 * typo, or a key an older version read, refuses the boot instead of being
 * dropped unread.
 */

import { fileURLToPath } from "node:url";
import { sectionStrictnessProblems } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { afterEach, describe, expect, it } from "vitest";
import { mfaModules } from "#/module.mjs";
import { configFor, disposeAll, MFA_KEY, refusal } from "./moduleHarness.mjs";

/** The package's defaults, as a composition root finds them. */
const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

/** The key no section declares. */
const UNKNOWN = "unknownKeyOfThisTest";

afterEach(disposeAll);

/** `tree` with the unknown key set in the object at `path`, copied along the way. */
function withUnknownKey(tree: unknown, path: readonly (string | number)[]): unknown {
	if (path.length === 0) return { ...(tree as Record<string, unknown>), [UNKNOWN]: "1" };
	const [head, ...rest] = path as [string | number, ...(string | number)[]];
	if (Array.isArray(tree)) {
		const copy = [...tree];
		copy[head as number] = withUnknownKey(tree[head as number], rest);
		return copy;
	}
	const object = tree as Record<string, unknown>;
	return { ...object, [head]: withUnknownKey(object[head], rest) };
}

describe("the package's sections", () => {
	it("refuse an unknown key at every object level, each level reached by the package's reference.conf", () => {
		const tree = parseFile(fileURLToPath(REFERENCE), {
			env: { MFA_ENCRYPTION_KEY: MFA_KEY },
		}).toObject();
		expect(sectionStrictnessProblems(mfaModules(), { tree })).toEqual([]);
	});

	it.each([
		[["mfa"]],
		[["mfa", "page"]],
		[["mfa", "encryptionKeys", 0]],
		[["mfa", "lockout"]],
		[["mfa", "rateLimit"]],
		[["mfa", "rateLimit", "routes"]],
		[["mfa", "manage"]],
		[["mfa", "enrollment"]],
		[["mfa-totp-factor"]],
	] as const)(
		"refuse the boot for an unknown key in %j, naming it at its path, before any factory runs",
		async (path) => {
			const err = await refusal({ config: withUnknownKey(configFor("required"), path) as never });
			expect(err.reason).toBe("config-validation-failed");
			expect(err.message).toContain(`${path.join(".")}: has a key it does not know: ${UNKNOWN}`);
		},
	);
});
