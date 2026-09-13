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
import { WEBAUTHN_ALGORITHM_IDS } from "#/index.mjs";

describe("WEBAUTHN_ALGORITHM_IDS on the barrel (v0.13.0 audit)", () => {
	it("is exported, since the README names it as the statement of the pin", () => {
		expect([...WEBAUTHN_ALGORITHM_IDS]).toEqual([-8, -7, -257]);
	});

	it("cannot be changed at runtime — the library's mutable default is what it replaced", () => {
		expect(Object.isFrozen(WEBAUTHN_ALGORITHM_IDS)).toBe(true);
	});
});
