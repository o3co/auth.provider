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
import { extractResourceParam, unrepresentedResources } from "#/grants/_resourceIndicator.mjs";

describe("extractResourceParam", () => {
	it("returns null when resource is absent", () => {
		expect(extractResourceParam({})).toBeNull();
	});

	it("returns null when resource is empty string", () => {
		expect(extractResourceParam({ resource: "" })).toBeNull();
	});

	it("wraps a single string value in an array", () => {
		expect(extractResourceParam({ resource: "https://rs1.example" })).toEqual([
			"https://rs1.example",
		]);
	});

	it("does NOT split on commas — URIs may contain commas (RFC 8707 §5.4)", () => {
		expect(extractResourceParam({ resource: "https://a,b.example" })).toEqual([
			"https://a,b.example",
		]);
	});

	it("returns the array as-is when resource is an array of strings", () => {
		expect(extractResourceParam({ resource: ["https://r1", "https://r2"] })).toEqual([
			"https://r1",
			"https://r2",
		]);
	});

	it("returns null for a non-string, non-array value (defensive)", () => {
		expect(extractResourceParam({ resource: 42 as unknown })).toBeNull();
	});

	it("returns null when the array contains a non-string element (defensive against mixed-type arrays)", () => {
		expect(extractResourceParam({ resource: ["https://r1", 42] as unknown })).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// Stage 2 — resource → audience representation (#173)
// ---------------------------------------------------------------------------

describe("unrepresentedResources", () => {
	/**
	 * RFC 8707 §2: the access token's audience must be the resource
	 * indicator(s) the client requested. `generateToken` carries a SINGLE
	 * `aud`, so "represented" reduces to string equality with that one value —
	 * and two distinct resources can never both be represented, no matter what
	 * the policy returns. That is not a limitation this helper imposes; it is
	 * the token shape, and the token-exchange grant already rejects on the
	 * same basis.
	 */
	it("returns nothing when no resource was requested", () => {
		expect(unrepresentedResources(null, "https://api.example")).toEqual([]);
		expect(unrepresentedResources(undefined, "https://api.example")).toEqual([]);
		expect(unrepresentedResources([], "https://api.example")).toEqual([]);
	});

	it("returns nothing when the single requested resource is the audience", () => {
		expect(unrepresentedResources(["https://api.example"], "https://api.example")).toEqual([]);
	});

	it("reports a requested resource the audience does not represent", () => {
		expect(unrepresentedResources(["https://other.example"], "https://api.example")).toEqual([
			"https://other.example",
		]);
	});

	it("reports every resource a single-valued audience cannot represent", () => {
		// The multi-resource case the issue left open: `aud` is one string, so
		// the second resource is unrepresentable by construction.
		expect(
			unrepresentedResources(
				["https://api.example", "https://other.example"],
				"https://api.example",
			),
		).toEqual(["https://other.example"]);
	});

	it("tolerates a repeated resource that matches the audience", () => {
		// Duplicates are not a widening — the client asked for one target twice.
		expect(
			unrepresentedResources(["https://api.example", "https://api.example"], "https://api.example"),
		).toEqual([]);
	});

	it("reports every requested resource when there is no audience at all", () => {
		// An unbound token represents nothing, so a resource request cannot be
		// satisfied — fail closed rather than minting an audience-less token.
		expect(unrepresentedResources(["https://api.example"], null)).toEqual(["https://api.example"]);
		expect(unrepresentedResources(["https://api.example"], undefined)).toEqual([
			"https://api.example",
		]);
	});
});
