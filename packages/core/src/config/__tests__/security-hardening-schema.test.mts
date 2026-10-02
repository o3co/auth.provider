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
 * Schema-level hardening of the token lifetimes an operator supplies: each is
 * a positive whole number and bounded, so an empty environment variable
 * (which HOCON substitutes as `""`) fails boot instead of minting a token that
 * expires at issue.
 */
import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";

function issuePaths(result: ReturnType<typeof AppConfigSchema.safeParse>): string[] {
	return result.success ? [] : result.error.issues.map((i) => i.path.join("."));
}

describe("token lifetimes are positive and bounded", () => {
	function parseWithOauth(patch: (base: ReturnType<typeof makeValidAppConfig>) => unknown) {
		const base = makeValidAppConfig();
		return AppConfigSchema.safeParse(patch(base));
	}

	it("rejects accessToken.expiresIn = 0", () => {
		const result = parseWithOauth((base) => ({
			...base,
			oauth: { ...base.oauth, accessToken: { expiresIn: 0 } },
		}));
		expect(result.success).toBe(false);
		expect(issuePaths(result)).toContain("oauth.accessToken.expiresIn");
	});

	it("rejects a negative accessToken.expiresIn", () => {
		const result = parseWithOauth((base) => ({
			...base,
			oauth: { ...base.oauth, accessToken: { expiresIn: -1 } },
		}));
		expect(result.success).toBe(false);
	});

	it("rejects refreshToken.expiresIn = 0", () => {
		const result = parseWithOauth((base) => ({
			...base,
			oauth: {
				...base.oauth,
				refreshToken: { ...base.oauth.refreshToken, expiresIn: 0 },
			},
		}));
		expect(result.success).toBe(false);
		expect(issuePaths(result)).toContain("oauth.refreshToken.expiresIn");
	});

	// `exp` is `iat + expiresIn`, which `generateToken` requires to be whole
	// seconds; the schema is where a loaded configuration meets that rule.
	for (const expiresIn of [1.5, Number.NaN, Number.POSITIVE_INFINITY, "1.5"]) {
		it(`rejects refreshToken.expiresIn = ${String(expiresIn)}: not a whole number of seconds`, () => {
			const result = parseWithOauth((base) => ({
				...base,
				oauth: {
					...base.oauth,
					refreshToken: { ...base.oauth.refreshToken, expiresIn },
				},
			}));
			expect(result.success).toBe(false);
			expect(issuePaths(result)).toContain("oauth.refreshToken.expiresIn");
		});
	}

	it("accepts the shipped defaults (3600s access, 86400s refresh)", () => {
		expect(AppConfigSchema.safeParse(makeValidAppConfig()).success).toBe(true);
	});
});
