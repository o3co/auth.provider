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
 * The one way a removed config key dies loudly (#366).
 *
 * Zod's default object behavior strips unknown keys before refinement sees
 * them, so an operator's stale config line would be silently ignored on
 * upgrade — the exact opposite of what a removal needs. The repo had grown
 * two copy-pasted preprocess wrappers doing the detection (refreshToken,
 * authorize) plus a differently-shaped one for the legacy JWT fields;
 * `withRemovedKeys` is the shared spelling, and this suite is its contract.
 */
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { type RemovedKey, withRemovedKeys } from "#/config/removed-keys.mjs";

const REMOVED: readonly RemovedKey[] = [
	{
		name: "oldFlag",
		removedIn: "v9.9.9 (test)",
		note: "It stopped meaning anything.",
	},
	{
		name: "otherFlag",
		removedIn: "v9.9.8 (test)",
		note: "Superseded by newFlag.",
	},
];

const schema = withRemovedKeys("test.section", REMOVED, z.object({ kept: z.string() }));

describe("withRemovedKeys", () => {
	it("passes a config that no longer sets any removed key", () => {
		expect(schema.parse({ kept: "value" })).toEqual({ kept: "value" });
	});

	it("refuses a config still setting a removed key, naming key, release, and note", () => {
		const result = schema.safeParse({ kept: "value", oldFlag: true });
		expect(result.success).toBe(false);
		const issue = result.success ? undefined : result.error.issues[0];
		// The message skeleton is shared with the pre-#366 wrappers, so the
		// operator-facing shape (and the tests pinning it) survive the
		// consolidation: "<section>.<key> was removed in <release>; see
		// CHANGELOG. <note> Remove this field from your config."
		expect(issue?.message).toContain("test.section.oldFlag was removed in v9.9.9 (test)");
		expect(issue?.message).toContain("see CHANGELOG");
		expect(issue?.message).toContain("It stopped meaning anything.");
		expect(issue?.message).toContain("Remove this field from your config.");
		expect(issue?.path).toEqual(["oldFlag"]);
	});

	it("reports every removed key present, not just the first", () => {
		const result = schema.safeParse({ kept: "value", oldFlag: 1, otherFlag: "x" });
		expect(result.success).toBe(false);
		const messages = result.success ? [] : result.error.issues.map((i) => i.message).join("\n");
		expect(messages).toContain("oldFlag");
		expect(messages).toContain("otherFlag");
	});

	it("leaves non-object input to the wrapped schema's own error", () => {
		// The detection must not crash on scalars/arrays; the wrapped schema
		// reports the type mismatch as it always did.
		expect(schema.safeParse("nonsense").success).toBe(false);
		expect(schema.safeParse([1, 2]).success).toBe(false);
	});
});
