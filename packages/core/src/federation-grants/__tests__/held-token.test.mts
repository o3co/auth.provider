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
	federationGrantAccessToken,
	federationGrantHeldToken,
} from "#/federation-grants/held-token.mjs";

const T0 = new Date("2026-09-18T00:00:00.000Z");
const at = (ms: number): Date => new Date(T0.getTime() + ms);
const token = { value: "at-1", tokenType: "Bearer", scopes: ["openid"] };

describe("federationGrantAccessToken", () => {
	it("keeps the three facts of the reading: when obtained, the lifetime issued, and when it ends", () => {
		expect(
			federationGrantAccessToken(token, {
				obtainedAt: T0,
				expiresAt: at(1_800_000),
				issuedLifetime: 3600,
			}),
		).toStrictEqual({
			...token,
			obtainedAt: T0,
			issuedLifetime: 3600,
			effectiveExpiresAt: at(1_800_000),
		});
	});
});

describe("federationGrantHeldToken", () => {
	const stored = { ...token, obtainedAt: T0, issuedLifetime: 3600 };

	it("ends a token without an effective end its issued lifetime after it was obtained", () => {
		expect(federationGrantHeldToken(stored)).toStrictEqual({
			obtainedAt: T0,
			expiresAt: at(3_600_000),
		});
	});

	it("ends a token at its effective end, and never later than its issued lifetime allows", () => {
		expect(
			federationGrantHeldToken({ ...stored, effectiveExpiresAt: at(1_800_000) }).expiresAt,
		).toEqual(at(1_800_000));
		expect(
			federationGrantHeldToken({ ...stored, effectiveExpiresAt: at(7_200_000) }).expiresAt,
		).toEqual(at(3_600_000));
	});

	it("reads an effective end that is not an instant as an end that is none", () => {
		const held = federationGrantHeldToken({ ...stored, effectiveExpiresAt: new Date(Number.NaN) });
		expect(Number.isNaN(held.expiresAt.getTime())).toBe(true);
	});
});
