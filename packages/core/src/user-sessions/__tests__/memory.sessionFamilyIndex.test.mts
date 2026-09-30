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
import { afterEach, describe, expect, it, vi } from "vitest";
import { createInMemorySessionFamilyIndex } from "../memory/sessionFamilyIndex.mjs";
import {
	runSessionEndContract,
	runSessionFamilyIndexContract,
} from "./sessionFamilyIndex.contract.mjs";

runSessionFamilyIndexContract(async () => createInMemorySessionFamilyIndex());
runSessionEndContract(async () => createInMemorySessionFamilyIndex());

describe("the memory index across two hosts' clocks", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("an end on a host whose clock is past expiresAt still marks the session: an add on a host whose clock is before it answers ended", async () => {
		const idx = createInMemorySessionFamilyIndex();
		const expiresAt = new Date(Date.now() + 60_000);
		const clock = vi.spyOn(Date, "now");
		clock.mockReturnValue(expiresAt.getTime() + 1_000);
		await idx.endSession("sid-1", expiresAt);
		clock.mockReturnValue(expiresAt.getTime() - 1_000);
		expect(await idx.addFamilyIdUnlessEnded("sid-1", "fam-A", expiresAt)).toBe("ended");
	});
});
