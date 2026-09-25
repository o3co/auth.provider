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
import { LIVENESS_SID_CLAIM, livenessSidOf } from "#/grants/sessionClaims.mjs";

describe("livenessSidOf", () => {
	it("names the claim a derived token carries its session under", () => {
		expect(LIVENESS_SID_CLAIM).toBe("liveness_sid");
	});

	it("reads a token's own sid first", () => {
		expect(livenessSidOf({ sid: "own", liveness_sid: "derived" })).toBe("own");
	});

	it("reads the liveness-only link of a token that has no sid", () => {
		expect(livenessSidOf({ liveness_sid: "derived" })).toBe("derived");
	});

	it("reads nothing from an empty or non-string value", () => {
		for (const claims of [
			{},
			{ sid: "" },
			{ sid: 7 },
			{ liveness_sid: "" },
			{ liveness_sid: [] },
		]) {
			expect(livenessSidOf(claims), JSON.stringify(claims)).toBeNull();
		}
		expect(livenessSidOf({ sid: "", liveness_sid: "derived" })).toBe("derived");
	});
});
