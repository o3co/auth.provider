/*
 * Copyright 2026 1o1 Inc.
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

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import bcrypt from "bcrypt";
import { afterEach, describe, expect, it } from "vitest";
import { StaticClientRepository } from "../StaticClientRepository.mjs";

function writeTempYaml(content: string): string {
	const tmpFile = path.join(
		os.tmpdir(),
		`clients-${Date.now()}-${Math.random().toString(36).slice(2)}.yaml`,
	);
	fs.writeFileSync(tmpFile, content, "utf-8");
	return tmpFile;
}

describe("StaticClientRepository", () => {
	const tempFiles: string[] = [];

	function createRepo(content: string): StaticClientRepository {
		const tmpFile = writeTempYaml(content);
		tempFiles.push(tmpFile);
		return new StaticClientRepository(tmpFile);
	}

	afterEach(() => {
		for (const f of tempFiles) {
			try {
				fs.unlinkSync(f);
			} catch {
				// ignore
			}
		}
		tempFiles.length = 0;
	});

	describe("constructor", () => {
		it("throws when file does not exist", () => {
			expect(() => new StaticClientRepository("/nonexistent/path/clients.yaml")).toThrow();
		});
	});

	describe("findById", () => {
		it("returns client when found", async () => {
			const repo = createRepo(`
test-app:
  clientSecret: "test-secret"
  allowedRedirectUris:
    - "http://localhost:3000/callback"
  allowedScopes:
    - "read"
    - "write"
`);
			const client = await repo.findById("test-app");
			expect(client).not.toBeNull();
			expect(client?.clientId).toBe("test-app");
			expect(client).not.toHaveProperty("clientSecret");
			expect(client?.allowedRedirectUris).toEqual(["http://localhost:3000/callback"]);
			expect(client?.allowedScopes).toEqual(["read", "write"]);
		});

		it("returns null when not found", async () => {
			const repo = createRepo(`
test-app:
  clientSecret: "test-secret"
  allowedRedirectUris: []
  allowedScopes: []
`);
			const client = await repo.findById("nonexistent-client");
			expect(client).toBeNull();
		});
	});

	describe("authenticate", () => {
		it("returns client with correct plain text secret", async () => {
			const repo = createRepo(`
my-client:
  clientSecret: "plain-secret"
  allowedRedirectUris: []
  allowedScopes: []
`);
			const client = await repo.authenticate("my-client", "plain-secret");
			expect(client).not.toBeNull();
			expect(client?.clientId).toBe("my-client");
			expect(client).not.toHaveProperty("clientSecret");
		});

		it("returns null with wrong plain text secret", async () => {
			const repo = createRepo(`
my-client:
  clientSecret: "plain-secret"
  allowedRedirectUris: []
  allowedScopes: []
`);
			const client = await repo.authenticate("my-client", "wrong-secret");
			expect(client).toBeNull();
		});

		it("returns null for nonexistent client", async () => {
			const repo = createRepo(`
my-client:
  clientSecret: "plain-secret"
  allowedRedirectUris: []
  allowedScopes: []
`);
			const client = await repo.authenticate("ghost-client", "plain-secret");
			expect(client).toBeNull();
		});

		it("returns client with correct bcrypt secret", async () => {
			const realHash = bcrypt.hashSync("my-secret", 10);
			const repo = createRepo(`
bcrypt-client:
  clientSecret: "${realHash}"
  allowedRedirectUris: []
  allowedScopes: []
`);
			const client = await repo.authenticate("bcrypt-client", "my-secret");
			expect(client).not.toBeNull();
			expect(client?.clientId).toBe("bcrypt-client");
		});

		it("returns null with wrong bcrypt secret", async () => {
			const realHash = bcrypt.hashSync("my-secret", 10);
			const repo = createRepo(`
bcrypt-client:
  clientSecret: "${realHash}"
  allowedRedirectUris: []
  allowedScopes: []
`);
			const client = await repo.authenticate("bcrypt-client", "wrong-secret");
			expect(client).toBeNull();
		});
	});

	describe("validation", () => {
		it("throws on invalid entry (missing clientSecret)", () => {
			expect(() =>
				createRepo(`
bad-client:
  allowedRedirectUris: []
  allowedScopes: []
`),
			).toThrow(/Invalid client entry "bad-client"/);
		});

		it("throws on invalid entry (allowedRedirectUris is string)", () => {
			expect(() =>
				createRepo(`
bad-client:
  clientSecret: "secret"
  allowedRedirectUris: "not-an-array"
  allowedScopes: []
`),
			).toThrow(/Invalid client entry "bad-client"/);
		});
	});
});
