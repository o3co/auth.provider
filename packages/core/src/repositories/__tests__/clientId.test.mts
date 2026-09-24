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
 * `isWellFormedClientId` — what a `client_id` from a request must look like
 * before a `ClientRepository` is asked for it. The routes' use of it is
 * pinned in `packages/oauth/src/__tests__/clientIdScreening.integration.test.mts`.
 */

import { describe, expect, it } from "vitest";
import { isWellFormedClientId, MAX_CLIENT_ID_LENGTH } from "#/repositories/clientId.mjs";

describe("isWellFormedClientId", () => {
	it("admits a registered id, a CIMD URL, and one at the length bound", () => {
		expect(isWellFormedClientId("my-app")).toBe(true);
		expect(isWellFormedClientId("https://app.example/oauth/client.json")).toBe(true);
		expect(isWellFormedClientId("c".repeat(MAX_CLIENT_ID_LENGTH))).toBe(true);
	});

	it("admits non-ASCII a registry may already hold", () => {
		expect(isWellFormedClientId("クライアント")).toBe(true);
	});

	it.each([
		["empty", ""],
		["past the length bound", "c".repeat(MAX_CLIENT_ID_LENGTH + 1)],
		["a NUL byte", "rp\u0000"],
		["a tab", "rp\tx"],
		["a line feed", "rp\nx"],
		["DEL", "rp\u007f"],
		["a C1 control character", "rp\u0085"],
		["the last C1 control character", "rp\u009f"],
	])("refuses %s", (_label, clientId) => {
		expect(isWellFormedClientId(clientId)).toBe(false);
	});

	it.each([
		["a number", 7],
		["an array", ["rp"]],
		["undefined", undefined],
	])("refuses %s", (_label, clientId) => {
		expect(isWellFormedClientId(clientId)).toBe(false);
	});
});
