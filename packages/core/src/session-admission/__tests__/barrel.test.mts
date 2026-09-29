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
 * What the package barrel exports of session admission (the session-admission
 * ADR's D1): the consumers' surface — the decision, the claim builders, the
 * establishment, `checkResolver` for a consumer factory built by hand,
 * `stepUpPageUrl` for a step-up's page, the checks a store runs — and none
 * of core's internals: registration, the seal, the continuation builders,
 * and what only admission itself calls.
 */

import { describe, expect, it } from "vitest";
import * as core from "#/index.mjs";

describe("the barrel's session-admission surface", () => {
	it("exports checkResolver, so a consumer factory outside core throws on a missing or forged resolver", () => {
		expect(typeof core.checkResolver).toBe("function");
		expect(() => core.checkResolver(undefined)).toThrow(RangeError);
		expect(() =>
			core.checkResolver({ get: () => undefined, entries: () => [][Symbol.iterator]() }),
		).toThrow(RangeError);
	});

	it("exports stepUpPageUrl, so every consumer answers a step-up's page as one absolute URL", () => {
		expect(typeof core.stepUpPageUrl).toBe("function");
		expect(core.stepUpPageUrl({ url: "/mfa", params: { flow: "x" } }, "https://auth.test")).toBe(
			"https://auth.test/mfa?flow=x",
		);
	});

	it("does not export what no consumer outside core calls: the acr selection, the establishment checks admission runs, admission's own store names and their predicate, the hint-key grammar", () => {
		// Admission's own: `selectAcr` has one product caller (admitSession);
		// the primary's checks run inside admitPrimary / resumePrimary; a
		// consumer describes an outage with describeAdmissionOutage, never by
		// the list; registration checks hint keys. Each stays exported from its
		// file for core.
		for (const internal of [
			"selectAcr",
			"checkPrimaryAuthentication",
			"checkPrimaryAdditions",
			"ADMISSION_INFRASTRUCTURE_STORES",
			"isAdmissionInfrastructureStore",
			"isHintKey",
		]) {
			expect(Object.hasOwn(core, internal), internal).toBe(false);
		}
		// What a consumer or a store does call stays.
		for (const kept of [
			"admitSession",
			"describeAdmissionOutage",
			"checkPrimaryContinuation",
			"isHintToken",
			"stepUpReach",
			"readAcrTable",
		]) {
			expect(Object.hasOwn(core, kept), kept).toBe(true);
		}
	});

	it("does not export boot's internals: registration, the seal and the continuation builders", () => {
		for (const internal of [
			"registeredRequirement",
			"sealRegisteredReach",
			"continuationOf",
			"primaryFromDto",
			"additionsFromDto",
		]) {
			expect(Object.hasOwn(core, internal), internal).toBe(false);
		}
	});
});
