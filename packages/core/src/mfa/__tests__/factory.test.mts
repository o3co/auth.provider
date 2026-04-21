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
import { createMfaProviderFactory } from "#/mfa/factory.mjs";
import { supportsEnrollment, supportsRevocation } from "#/mfa/types.mjs";
import { createTestMfaProvider, createTestMfaProviderWithCapabilities } from "./fixtures.mjs";

describe("createMfaProviderFactory", () => {
	it("creates an adapter factory and resolves registered providers", async () => {
		const factory = createMfaProviderFactory();
		factory.register("totp", () => createTestMfaProvider({ kind: "totp" }));
		const provider = await factory.create({ type: "totp" });
		expect(provider.kind).toBe("totp");
	});

	it("throws on unknown kind via AdapterFactoryError", async () => {
		const factory = createMfaProviderFactory();
		await expect(factory.create({ type: "missing" })).rejects.toThrow();
	});
});

describe("MfaProviderBase contract", () => {
	it("verify returns success/failureReason without throwing on invalid proof", async () => {
		const provider = createTestMfaProvider({
			kind: "totp",
			onVerify: async (_id, proof) => {
				if (typeof proof !== "object" || proof === null || !("code" in proof)) {
					return { success: false, failureReason: "invalid" };
				}
				return { success: true };
			},
		});
		const result1 = await provider.verify("cid", "not-an-object");
		expect(result1.success).toBe(false);
		expect(result1.failureReason).toBe("invalid");
		const result2 = await provider.verify("cid", { code: "123456" });
		expect(result2.success).toBe(true);
	});

	it("supportsEnrollment / supportsRevocation detect capability presence", () => {
		const base = createTestMfaProvider({ kind: "base" });
		expect(supportsEnrollment(base)).toBe(false);
		expect(supportsRevocation(base)).toBe(false);
		const cap = createTestMfaProviderWithCapabilities({ kind: "full" });
		expect(supportsEnrollment(cap)).toBe(true);
		expect(supportsRevocation(cap)).toBe(true);
	});

	it("supportsEnrollment / supportsRevocation safely reject null / undefined", () => {
		expect(supportsEnrollment(null)).toBe(false);
		expect(supportsEnrollment(undefined)).toBe(false);
		expect(supportsRevocation(null)).toBe(false);
		expect(supportsRevocation(undefined)).toBe(false);
	});
});
