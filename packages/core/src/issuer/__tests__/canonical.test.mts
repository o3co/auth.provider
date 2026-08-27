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
import {
	checkCanonicalIssuer,
	describeIssuerRejection,
	type IssuerRejection,
	isCanonicalIssuer,
} from "#/issuer/canonical.mjs";

describe("checkCanonicalIssuer", () => {
	it.each([
		"https://auth.example.com",
		"https://auth.example.com/tenant-a",
		"https://auth.example.com:8443",
		"http://localhost:3000",
		"http://127.0.0.1:3000",
		"http://[::1]:3000",
	])("accepts %s", (value) => {
		expect(checkCanonicalIssuer(value)).toBeNull();
		expect(isCanonicalIssuer(value)).toBe(true);
	});

	it.each([
		[undefined, "not-a-string"],
		[42, "not-a-string"],
		["", "empty"],
		// The shape a Host header supplies — the fallback this validation replaced.
		["auth.example.com:3000", "not-absolute-url"],
		["/oauth", "not-absolute-url"],
		["ftp://auth.example.com", "unsupported-scheme"],
		["http://auth.example.com", "insecure-scheme"],
		// OIDC derives the discovery URL from the issuer, so either would name a
		// document the provider does not serve.
		["https://auth.example.com?tenant=a", "has-query"],
		["https://auth.example.com#a", "has-fragment"],
		["https://user:pw@auth.example.com", "has-credentials"],
	])("rejects %j as %s", (value, reason) => {
		expect(checkCanonicalIssuer(value)).toBe(reason);
		expect(isCanonicalIssuer(value)).toBe(false);
	});
});

describe("describeIssuerRejection", () => {
	// Every rejection reaches an operator as a boot-failure message, so each one
	// has to say something specific about what is wrong with the value.
	const reasons: IssuerRejection[] = [
		"not-a-string",
		"empty",
		"not-absolute-url",
		"unsupported-scheme",
		"insecure-scheme",
		"has-query",
		"has-fragment",
		"has-credentials",
	];

	it.each(reasons)("explains %s", (reason) => {
		const message = describeIssuerRejection(reason);
		expect(message).toMatch(/^must /);
	});

	it("gives every reason a distinct explanation", () => {
		const messages = reasons.map(describeIssuerRejection);
		expect(new Set(messages).size).toBe(reasons.length);
	});

	it("names the loopback exception when https is missing", () => {
		expect(describeIssuerRejection("insecure-scheme")).toContain("localhost");
	});
});
