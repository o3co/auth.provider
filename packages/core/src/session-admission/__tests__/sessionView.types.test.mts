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
 * What the public entries promise about a session's view: every
 * `SessionView` says whether a second factor can be recorded on the session,
 * and `mergeAdmission` is always told the store the admission ran over, or
 * `undefined` for none. These are type assertions: the file is in core's
 * typecheck list.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { SessionView } from "#/index.mjs";
import { mergeAdmission } from "#/testing/index.mjs";
import type { UserSessionStore } from "#/user-sessions/types.mjs";

describe("SessionView", () => {
	it("is not built by hand without saying whether a second factor can be recorded on the session", () => {
		// @ts-expect-error a view without the field is not a SessionView
		const partial: SessionView = {
			sid: "sid-1",
			sub: "user-1",
			authTime: new Date(0),
			expiresAt: new Date(0),
		};
		expect(partial.sid).toBe("sid-1");
	});
});

describe("mergeAdmission", () => {
	it("takes the store the admission ran over as a required argument, undefined for none", () => {
		expectTypeOf<Parameters<typeof mergeAdmission>["length"]>().toEqualTypeOf<4>();
		expectTypeOf(mergeAdmission).parameter(3).toEqualTypeOf<UserSessionStore | undefined>();
		// @ts-expect-error the store is required
		expect(() => mergeAdmission({ outcome: "met", acr: undefined }, null, undefined)).not.toThrow();
	});
});
