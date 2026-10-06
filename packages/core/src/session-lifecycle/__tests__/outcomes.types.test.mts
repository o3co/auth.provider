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
 * The session lifecycle's answers name only what it decided: an outage
 * rejects with the store's own error, so no answer stands for one.
 */

import { describe, expectTypeOf, it } from "vitest";
import type {
	SessionCloseOutcome,
	SessionFederations,
	SessionJoinOutcome,
	SessionLiveness,
	SessionOpenOutcome,
} from "../service.mjs";

describe("the session lifecycle's outcomes", () => {
	it("name only what the lifecycle decided", () => {
		expectTypeOf<SessionOpenOutcome["outcome"]>().toEqualTypeOf<"opened" | "refused">();
		expectTypeOf<SessionJoinOutcome["outcome"]>().toEqualTypeOf<"joined" | "refused">();
		expectTypeOf<SessionCloseOutcome["outcome"]>().toEqualTypeOf<"done" | "pending">();
		expectTypeOf<SessionFederations["outcome"]>().toEqualTypeOf<"listed">();
		expectTypeOf<SessionLiveness["outcome"]>().toEqualTypeOf<"live" | "not_live">();
	});
});
