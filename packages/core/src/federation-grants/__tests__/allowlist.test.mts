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
import { federationGrantAllowlist } from "../allowlist.mjs";

describe("federationGrantAllowlist", () => {
	it("keeps an array of strings as it is", () => {
		expect(federationGrantAllowlist(["calendar", "mail"])).toEqual(["calendar", "mail"]);
		expect(federationGrantAllowlist([])).toEqual([]);
	});

	it("reads anything that is not an array as an empty list — a string included, so a substring is never a match", () => {
		for (const value of [
			undefined,
			null,
			"calendar,mail",
			"calendar",
			1,
			true,
			{ 0: "calendar" },
		]) {
			expect(federationGrantAllowlist(value)).toEqual([]);
		}
	});

	it("drops the entries of an array that are not strings, and keeps the rest", () => {
		expect(federationGrantAllowlist(["calendar", 1, null, undefined, ["mail"], "mail"])).toEqual([
			"calendar",
			"mail",
		]);
	});
});
