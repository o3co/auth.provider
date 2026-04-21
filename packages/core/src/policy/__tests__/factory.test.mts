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
import { createGrantPolicyHookFactory } from "#/policy/factory.mjs";
import type { GrantPolicyDecision } from "#/policy/types.mjs";

describe("createGrantPolicyHookFactory", () => {
	it("resolves registered hooks and honors allow with narrow", async () => {
		const factory = createGrantPolicyHookFactory();
		factory.register("narrowing", () => ({
			kind: "narrowing",
			async evaluate(req): Promise<GrantPolicyDecision> {
				return {
					outcome: "allow",
					grantedScope: req.requestedScope?.slice(0, 1) ?? [],
				};
			},
		}));
		const hook = await factory.create({ type: "narrowing" });
		const result = await hook.evaluate(
			{
				grantType: "authorization_code",
				requestedScope: ["a", "b", "c"],
			},
			{ issuer: "https://auth.example" },
		);
		expect(result.outcome).toBe("allow");
		if (result.outcome === "allow") {
			expect(result.grantedScope).toEqual(["a"]);
		}
	});

	it("returns deny outcomes with OAuth error codes", async () => {
		const factory = createGrantPolicyHookFactory();
		factory.register("denying", () => ({
			kind: "denying",
			async evaluate(): Promise<GrantPolicyDecision> {
				return { outcome: "deny", error: "invalid_scope", errorDescription: "too broad" };
			},
		}));
		const hook = await factory.create({ type: "denying" });
		const result = await hook.evaluate({ grantType: "refresh_token" }, { issuer: "x" });
		expect(result.outcome).toBe("deny");
		if (result.outcome === "deny") {
			expect(result.error).toBe("invalid_scope");
		}
	});
});
