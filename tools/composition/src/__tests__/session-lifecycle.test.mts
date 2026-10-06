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
 * Every workspace package booted together, the template's composition with
 * core's session lifecycle module in it: the composition serves relying
 * parties, so boot holds it to a session-close notifier, which the oauth
 * module contributes.
 */

import type { SessionLifecycle } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { composeFullSet } from "./full-set.fixture.mjs";

describe("the full set, which composes the session lifecycle module", () => {
	it("boots, the oauth module's notifier contributed", async () => {
		const { handle } = await composeFullSet();
		try {
			const lifecycle = handle.components.sessionLifecycle as SessionLifecycle | undefined;
			expect(lifecycle).toBeDefined();
			expect(handle.components.sessionCloseNotifierResolver?.get()).toBeDefined();
		} finally {
			await handle.dispose();
		}
	});
});
