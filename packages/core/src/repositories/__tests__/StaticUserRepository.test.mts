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
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { StaticUserRepository } from "../StaticUserRepository.mjs";

describe("StaticUserRepository", () => {
	let tmpDir: string;
	let filePath: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "static-user-repo-"));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	const writeYaml = (content: string): string => {
		filePath = path.join(tmpDir, "users.yaml");
		fs.writeFileSync(filePath, content);
		return filePath;
	};

	describe("constructor", () => {
		it("loads users from YAML file", () => {
			const fp = writeYaml(`
alice:
  password: secret123
  id: u1
`);
			const repo = new StaticUserRepository(fp);
			expect(repo).toBeDefined();
		});

		it("accepts empty YAML file", () => {
			const fp = writeYaml("");
			const repo = new StaticUserRepository(fp);
			expect(repo).toBeDefined();
		});

		it("throws on invalid YAML structure", () => {
			const fp = writeYaml("- not\n- a mapping");
			expect(() => new StaticUserRepository(fp)).toThrow("expected a YAML mapping");
		});

		it("throws on missing password field", () => {
			const fp = writeYaml(`
alice:
  id: u1
`);
			expect(() => new StaticUserRepository(fp)).toThrow("password");
		});
	});

	describe("authenticate", () => {
		it("returns user for valid credentials (plain text)", async () => {
			const fp = writeYaml(`
alice:
  password: secret123
  id: u1
  email: alice@example.com
`);
			const repo = new StaticUserRepository(fp);
			const user = await repo.authenticate("alice", "secret123");

			expect(user).not.toBeNull();
			expect(user?.id).toBe("u1");
			expect(user?.username).toBe("alice");
			expect(user?.email).toBe("alice@example.com");
		});

		it("returns null for wrong password", async () => {
			const fp = writeYaml(`
alice:
  password: secret123
  id: u1
`);
			const repo = new StaticUserRepository(fp);
			const user = await repo.authenticate("alice", "wrong");

			expect(user).toBeNull();
		});

		it("returns null for unknown username", async () => {
			const fp = writeYaml(`
alice:
  password: secret123
  id: u1
`);
			const repo = new StaticUserRepository(fp);
			const user = await repo.authenticate("bob", "secret123");

			expect(user).toBeNull();
		});

		it("supports bcrypt hashed passwords", async () => {
			const bcrypt = await import("bcrypt");
			const hash = await bcrypt.hash("secret123", 10);
			const fp = writeYaml(`
alice:
  password: "${hash}"
  id: u1
`);
			const repo = new StaticUserRepository(fp);
			const user = await repo.authenticate("alice", "secret123");

			expect(user).not.toBeNull();
			expect(user?.username).toBe("alice");
		});

		it("does not include password in returned user", async () => {
			const fp = writeYaml(`
alice:
  password: secret123
  id: u1
`);
			const repo = new StaticUserRepository(fp);
			const user = await repo.authenticate("alice", "secret123");

			expect(user).not.toBeNull();
			expect((user as Record<string, unknown>).password).toBeUndefined();
		});
	});

	describe("authenticateByToken", () => {
		it("returns user matching token field", async () => {
			const fp = writeYaml(`
alice:
  password: secret123
  id: u1
  token: tok_alice_123
`);
			const repo = new StaticUserRepository(fp);
			const user = await repo.authenticateByToken("tok_alice_123");

			expect(user).not.toBeNull();
			expect(user?.username).toBe("alice");
		});

		it("returns null when no user has matching token", async () => {
			const fp = writeYaml(`
alice:
  password: secret123
  id: u1
  token: tok_alice_123
`);
			const repo = new StaticUserRepository(fp);
			const user = await repo.authenticateByToken("tok_unknown");

			expect(user).toBeNull();
		});

		it("returns null when no users have token field", async () => {
			const fp = writeYaml(`
alice:
  password: secret123
  id: u1
`);
			const repo = new StaticUserRepository(fp);
			const user = await repo.authenticateByToken("tok_anything");

			expect(user).toBeNull();
		});
	});
});
