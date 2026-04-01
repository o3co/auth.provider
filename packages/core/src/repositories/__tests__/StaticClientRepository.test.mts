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
import bcrypt from "bcrypt";
import { describe, expect, it } from "vitest";
import { StaticClientRepository } from "../StaticClientRepository.mjs";

describe("StaticClientRepository", () => {
	describe("findById", () => {
		it("returns client when found", async () => {
			const repo = new StaticClientRepository(
				new Map([
					[
						"test-app",
						{
							clientSecret: "test-secret",
							allowedRedirectUris: ["http://localhost:3000/callback"],
							allowedScopes: ["read", "write"],
						},
					],
				]),
			);
			const client = await repo.findById("test-app");
			expect(client).not.toBeNull();
			expect(client?.clientId).toBe("test-app");
			expect(client).not.toHaveProperty("clientSecret");
			expect(client?.allowedRedirectUris).toEqual(["http://localhost:3000/callback"]);
			expect(client?.allowedScopes).toEqual(["read", "write"]);
		});

		it("returns null when not found", async () => {
			const repo = new StaticClientRepository(
				new Map([
					[
						"test-app",
						{
							clientSecret: "test-secret",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.findById("nonexistent-client");
			expect(client).toBeNull();
		});
	});

	describe("authenticate", () => {
		it("returns client with correct plain text secret", async () => {
			const repo = new StaticClientRepository(
				new Map([
					[
						"my-client",
						{
							clientSecret: "plain-secret",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.authenticate("my-client", "plain-secret");
			expect(client).not.toBeNull();
			expect(client?.clientId).toBe("my-client");
			expect(client).not.toHaveProperty("clientSecret");
		});

		it("returns null with wrong plain text secret", async () => {
			const repo = new StaticClientRepository(
				new Map([
					[
						"my-client",
						{
							clientSecret: "plain-secret",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.authenticate("my-client", "wrong-secret");
			expect(client).toBeNull();
		});

		it("returns null for nonexistent client", async () => {
			const repo = new StaticClientRepository(
				new Map([
					[
						"my-client",
						{
							clientSecret: "plain-secret",
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.authenticate("ghost-client", "plain-secret");
			expect(client).toBeNull();
		});

		it("returns client with correct bcrypt secret", async () => {
			const realHash = bcrypt.hashSync("my-secret", 10);
			const repo = new StaticClientRepository(
				new Map([
					[
						"bcrypt-client",
						{
							clientSecret: realHash,
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.authenticate("bcrypt-client", "my-secret");
			expect(client).not.toBeNull();
			expect(client?.clientId).toBe("bcrypt-client");
		});

		it("returns null with wrong bcrypt secret", async () => {
			const realHash = bcrypt.hashSync("my-secret", 10);
			const repo = new StaticClientRepository(
				new Map([
					[
						"bcrypt-client",
						{
							clientSecret: realHash,
							allowedRedirectUris: [],
							allowedScopes: [],
						},
					],
				]),
			);
			const client = await repo.authenticate("bcrypt-client", "wrong-secret");
			expect(client).toBeNull();
		});
	});
});
