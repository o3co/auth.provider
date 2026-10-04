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
 * `device-grant.rateLimit`: the verification endpoint's own attempt limit,
 * which RFC 8628 §5.1 sizes the user code against. Pins both ends: the
 * schema boundary (the shipped default and the bounds, the window at most a
 * day, the longest a counter takes), and the documented key in
 * `reference.conf` resolving, through the real HOCON parser, the spec the
 * module reads and core's in-process attempt counter, to five attempts.
 */

import { fileURLToPath } from "node:url";
import { createMemoryAttemptCounter } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { deviceGrantConfigSchema } from "#/module.mjs";
import { readVerificationAttemptSpec } from "#/verificationAttempts.mjs";
import { shippedDeviceGrantSection } from "./shippedSection.mjs";

const REFERENCE_CONF = fileURLToPath(new URL("../../config/reference.conf", import.meta.url));

describe("device-grant.rateLimit — schema boundary", () => {
	it("ships RFC 8628 §5.1's five attempts per five minutes", () => {
		// §5.1's worked example: ~34.5 bits is sufficient only where "the
		// rate-limiting interval and validity period would need to only
		// allow 5 attempts". Five minutes is half the default code lifetime.
		const parsed = deviceGrantConfigSchema.parse(shippedDeviceGrantSection());
		expect(parsed?.rateLimit).toEqual({ limit: 5, windowSeconds: 300 });
	});

	it("holds no default of its own: a section written without a limit refuses, naming it", () => {
		const { rateLimit: _rateLimit, ...withoutLimit } = shippedDeviceGrantSection();
		const result = deviceGrantConfigSchema.safeParse(withoutLimit);
		expect(result.error?.issues.map((issue) => issue.path.join("."))).toEqual(["rateLimit"]);
	});

	it("accepts an operator's own limit, up to a day's window", () => {
		for (const rateLimit of [
			{ limit: 3, windowSeconds: 600 },
			{ limit: 3, windowSeconds: 86_400 },
		]) {
			const parsed = deviceGrantConfigSchema.parse(shippedDeviceGrantSection({ rateLimit }));
			expect(parsed?.rateLimit).toEqual(rateLimit);
		}
	});

	it.each([
		["a zero limit", { limit: 0, windowSeconds: 300 }],
		["a zero window", { limit: 5, windowSeconds: 0 }],
		["a negative limit", { limit: -5, windowSeconds: 300 }],
		["a fractional limit", { limit: 2.5, windowSeconds: 300 }],
		["a fractional window", { limit: 5, windowSeconds: 0.5 }],
		["a window longer than a day", { limit: 5, windowSeconds: 86_401 }],
		["a window past the Date range", { limit: 5, windowSeconds: 1e13 }],
		["a missing field", { limit: 5 }],
	])("refuses %s at the config boundary", (_label, rateLimit) => {
		// A zero here is not "no limit" — it is what an empty environment
		// variable coerces to, and a zero-attempt limit locks every user out
		// while a zero window is not a window. Both fail boot, loudly.
		const result = deviceGrantConfigSchema.safeParse(shippedDeviceGrantSection({ rateLimit }));
		expect(result.success).toBe(false);
	});
});

describe("device-grant.rateLimit — the documented key resolves", () => {
	it("counts five attempts per subject from reference.conf alone", async () => {
		// The shipped HOCON defaults and the schema, the spec the module reads
		// from them, counted on core's in-process counter under the key the
		// verification endpoint uses. The sixth attempt is the one refused.
		const parsed = deviceGrantConfigSchema.parse(
			(parseFile(REFERENCE_CONF).toObject() as { "device-grant": unknown })["device-grant"],
		);
		const spec = readVerificationAttemptSpec(parsed);
		expect(spec).toEqual({ limit: 5, windowSeconds: 300 });

		const counter = createMemoryAttemptCounter();
		const outcomes: boolean[] = [];
		for (let i = 0; i < 6; i += 1) {
			outcomes.push((await counter.consume("device_verification:user:user-1", spec)).allowed);
		}
		expect(outcomes).toEqual([true, true, true, true, true, false]);
	});
});
