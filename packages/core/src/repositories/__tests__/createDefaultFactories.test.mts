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
import { createDefaultFactories } from "#/repositories/RepositoryFactory.mjs";

describe("createDefaultFactories", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "create-default-factories-"));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	const writeYaml = (filename: string, content: string): string => {
		const fp = path.join(tmpDir, filename);
		fs.writeFileSync(fp, content);
		return fp;
	};

	describe("clientFactory", () => {
		it("creates a client repository from yaml config and supports findById", async () => {
			const yamlPath = writeYaml(
				"clients.yaml",
				`my-client:
  clientSecret: "secret123"
  allowedRedirectUris:
    - "http://localhost:3000/callback"
  allowedScopes:
    - "read"
`,
			);

			const { clientFactory } = createDefaultFactories();
			const repo = await clientFactory.create({ type: "yaml", path: yamlPath });
			const client = await repo.findById("my-client");

			expect(client).not.toBeNull();
			expect(client?.clientId).toBe("my-client");
			expect(client?.allowedRedirectUris).toEqual(["http://localhost:3000/callback"]);
			expect(client?.allowedScopes).toEqual(["read"]);
		});

		it("throws for unregistered type", async () => {
			const { clientFactory } = createDefaultFactories();
			await expect(clientFactory.create({ type: "redis" })).rejects.toThrow(
				/Unknown client repository type: "redis"/,
			);
		});
	});

	describe("userFactory", () => {
		it("creates a user repository from yaml config and supports authenticate", async () => {
			const yamlPath = writeYaml(
				"users.yaml",
				`alice:
  password: "plainpass"
`,
			);

			const { userFactory } = createDefaultFactories();
			const repo = await userFactory.create({ type: "yaml", path: yamlPath });
			const user = await repo.authenticate("alice", "plainpass");

			expect(user).not.toBeNull();
			expect(user?.username).toBe("alice");
		});

		it("throws for unregistered type", async () => {
			const { userFactory } = createDefaultFactories();
			await expect(userFactory.create({ type: "http" })).rejects.toThrow(
				/Unknown user repository type: "http"/,
			);
		});
	});

	describe("codeFactory", () => {
		it("creates a code repository from memory config and supports createCode/getByCode", async () => {
			const { codeFactory } = createDefaultFactories();
			const repo = await codeFactory.create({ type: "memory" });
			const code = await repo.createCode({});

			expect(code.code).toBeDefined();
			const fetched = await repo.getByCode(code.code);
			expect(fetched).not.toBeNull();
			expect(fetched?.code).toBe(code.code);
		});

		it("rejects non-numeric defaultExpiresIn", async () => {
			const { codeFactory } = createDefaultFactories();
			await expect(
				codeFactory.create({ type: "memory", defaultExpiresIn: "not-a-number" }),
			).rejects.toThrow('"defaultExpiresIn" must be a finite positive number');
		});

		it("rejects Infinity defaultExpiresIn", async () => {
			const { codeFactory } = createDefaultFactories();
			await expect(
				codeFactory.create({ type: "memory", defaultExpiresIn: Infinity }),
			).rejects.toThrow('"defaultExpiresIn" must be a finite positive number');
		});

		it("rejects negative defaultExpiresIn", async () => {
			const { codeFactory } = createDefaultFactories();
			await expect(
				codeFactory.create({ type: "memory", defaultExpiresIn: -1 }),
			).rejects.toThrow('"defaultExpiresIn" must be a finite positive number');
		});

		it("rejects zero defaultExpiresIn", async () => {
			const { codeFactory } = createDefaultFactories();
			await expect(
				codeFactory.create({ type: "memory", defaultExpiresIn: 0 }),
			).rejects.toThrow('"defaultExpiresIn" must be a finite positive number');
		});

		it("throws for unregistered type", async () => {
			const { codeFactory } = createDefaultFactories();
			await expect(codeFactory.create({ type: "redis" })).rejects.toThrow(
				/Unknown code repository type: "redis"/,
			);
		});
	});
});
