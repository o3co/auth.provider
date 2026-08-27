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

import type { UserSessionClaims } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	FEDERATED_CLAIMS_KEY,
	mergeFederatedClaims,
	PROMOTABLE_FEDERATED_CLAIMS,
} from "#/federations/claim-precedence.mjs";

const namespaceOf = (claims: UserSessionClaims, provider = "test"): Record<string, unknown> => {
	const ns = (claims as Record<string, unknown>)[FEDERATED_CLAIMS_KEY] as
		| Record<string, Record<string, unknown>>
		| undefined;
	return ns?.[provider] ?? {};
};

describe("mergeFederatedClaims — precedence (#279)", () => {
	describe("the promotable set", () => {
		it("contains only non-authorization profile claims", () => {
			expect([...PROMOTABLE_FEDERATED_CLAIMS]).toEqual(["email", "name", "picture"]);
		});

		it("excludes every authorization-bearing and verification-bearing claim", () => {
			// The point of #279: no federated value may reach these, and the set is
			// the machine-readable statement of that. `emailVerified` is here because
			// #297 made it a contract-bearing field that can gate token issuance.
			for (const forbidden of ["groups", "roles", "emailVerified", "scope", "permissions"]) {
				expect(PROMOTABLE_FEDERATED_CLAIMS as readonly string[]).not.toContain(forbidden);
			}
		});
	});

	describe("local claims are authoritative", () => {
		it("never overwrites a local claim with a federated one", () => {
			const claims = mergeFederatedClaims({
				localClaims: {
					email: "local@example.test",
					name: "Local Name",
					picture: "https://local.example.test/p.png",
					groups: ["staff"],
				},
				providerName: "test",
				mappedClaims: {
					email: "spoofed@example.test",
					name: "Spoofed Name",
					picture: "https://idp.example.test/p.png",
					groups: ["admin"],
				},
			});

			expect(claims.email).toBe("local@example.test");
			expect(claims.name).toBe("Local Name");
			expect(claims.picture).toBe("https://local.example.test/p.png");
			expect(claims.groups).toEqual(["staff"]);
		});

		it("returns the local claims unchanged when the provider maps nothing", () => {
			const local: UserSessionClaims = { email: "local@example.test", groups: ["staff"] };
			const claims = mergeFederatedClaims({
				localClaims: local,
				providerName: "test",
				mappedClaims: undefined,
			});

			expect(claims).toEqual(local);
			expect(claims).not.toHaveProperty(FEDERATED_CLAIMS_KEY);
		});
	});

	describe("authorization claims are structurally unreachable", () => {
		it("does not let a federated groups become the top-level groups, even with no local groups", () => {
			const claims = mergeFederatedClaims({
				localClaims: { email: "local@example.test" },
				providerName: "test",
				mappedClaims: { groups: ["admin", "billing"] },
			});

			expect(claims.groups).toBeUndefined();
			expect(namespaceOf(claims).groups).toEqual(["admin", "billing"]);
		});

		it("does not let a federated roles reach the top-level envelope", () => {
			const claims = mergeFederatedClaims({
				localClaims: { email: "local@example.test" },
				providerName: "test",
				mappedClaims: { roles: ["superuser"] },
			});

			expect((claims as Record<string, unknown>).roles).toBeUndefined();
			expect(namespaceOf(claims).roles).toEqual(["superuser"]);
		});

		it("promotes nothing outside the promotable set, whatever the adapter maps", () => {
			const hostile = {
				groups: ["admin"],
				roles: ["superuser"],
				emailVerified: true,
				scope: "admin",
				permissions: ["*"],
				sub: "attacker",
				iss: "https://evil.example.test",
				amr: ["mfa"],
				acr: "urn:high",
				hd: "corp.example.test",
			};
			const claims = mergeFederatedClaims({
				localClaims: {},
				providerName: "test",
				mappedClaims: hostile,
			});

			for (const key of Object.keys(hostile)) {
				expect((claims as Record<string, unknown>)[key]).toBeUndefined();
				expect(namespaceOf(claims)[key]).toEqual((hostile as Record<string, unknown>)[key]);
			}
		});
	});

	describe("emailVerified is Store-owned (#297) and federation cannot write it", () => {
		it("does not set emailVerified when the local record does not model it", () => {
			const claims = mergeFederatedClaims({
				localClaims: {},
				providerName: "test",
				mappedClaims: { email: "user@example.test", emailVerified: true },
			});

			// Absent, not false: absence says "the Store does not model verification".
			expect(claims).not.toHaveProperty("emailVerified");
			expect(namespaceOf(claims).emailVerified).toBe(true);
		});

		it("does not flip a local emailVerified:false to true", () => {
			const claims = mergeFederatedClaims({
				localClaims: { email: "local@example.test", emailVerified: false },
				providerName: "test",
				mappedClaims: { email: "local@example.test", emailVerified: true },
			});

			expect(claims.emailVerified).toBe(false);
		});
	});

	describe("gap filling", () => {
		it("fills a promotable claim the local record left absent", () => {
			const claims = mergeFederatedClaims({
				localClaims: { groups: ["staff"] },
				providerName: "test",
				mappedClaims: {
					email: "user@idp.example.test",
					name: "Idp Name",
					picture: "https://idp.example.test/p.png",
				},
			});

			expect(claims.email).toBe("user@idp.example.test");
			expect(claims.name).toBe("Idp Name");
			expect(claims.picture).toBe("https://idp.example.test/p.png");
			expect(claims.groups).toEqual(["staff"]);
		});

		it("fills a federated email without asserting its verification", () => {
			const claims = mergeFederatedClaims({
				localClaims: {},
				providerName: "test",
				mappedClaims: { email: "user@idp.example.test", emailVerified: true },
			});

			expect(claims.email).toBe("user@idp.example.test");
			expect(claims).not.toHaveProperty("emailVerified");
		});

		it("drops a promotable claim whose federated value is not a string", () => {
			const claims = mergeFederatedClaims({
				localClaims: {},
				providerName: "test",
				mappedClaims: { email: { toString: "x" }, name: 42, picture: ["https://x.example"] },
			});

			expect(claims.email).toBeUndefined();
			expect(claims.name).toBeUndefined();
			expect(claims.picture).toBeUndefined();
		});
	});

	describe("the provider namespace", () => {
		it("records the mapped snapshot under the provider name", () => {
			const claims = mergeFederatedClaims({
				localClaims: { email: "local@example.test" },
				providerName: "google",
				mappedClaims: { email: "user@idp.example.test", hd: "corp.example.test" },
			});

			expect((claims as Record<string, unknown>)[FEDERATED_CLAIMS_KEY]).toEqual({
				google: { email: "user@idp.example.test", hd: "corp.example.test" },
			});
		});

		it("keeps the rejected federated value verbatim, so nothing is silently lost", () => {
			const claims = mergeFederatedClaims({
				localClaims: { email: "local@example.test" },
				providerName: "test",
				mappedClaims: { email: "user@idp.example.test" },
			});

			expect(claims.email).toBe("local@example.test");
			expect(namespaceOf(claims).email).toBe("user@idp.example.test");
		});

		it("is omitted when the provider contributed no claims", () => {
			const claims = mergeFederatedClaims({
				localClaims: { email: "local@example.test" },
				providerName: "test",
				mappedClaims: {},
			});

			expect(claims).not.toHaveProperty(FEDERATED_CLAIMS_KEY);
		});

		it("does not alias the mapped object it was handed", () => {
			const mapped: Record<string, unknown> = { hd: "corp.example.test" };
			const claims = mergeFederatedClaims({
				localClaims: {},
				providerName: "test",
				mappedClaims: mapped,
			});
			mapped.groups = ["admin"];

			expect(namespaceOf(claims)).toEqual({ hd: "corp.example.test" });
		});
	});

	describe("hostile adapter return values", () => {
		it.each([
			["null", null],
			["a string", "admin"],
			["an array", [{ groups: ["admin"] }]],
			["a number", 7],
		])("treats %s as no mapped claims", (_label, mappedClaims) => {
			const local: UserSessionClaims = { email: "local@example.test", groups: ["staff"] };
			const claims = mergeFederatedClaims({
				localClaims: local,
				providerName: "test",
				mappedClaims,
			});

			expect(claims).toEqual(local);
		});
	});
});
