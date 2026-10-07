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
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AdapterFactoryError } from "#/adapters/AdapterFactory.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { createRepositoryFactories } from "#/repositories/RepositoryFactory.mjs";

describe("createRepositoryFactories", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "create-repository-factories-"));
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
  tokenEndpointAuthMethod: "client_secret_basic"
  clientSecret: "secret123"
  allowedRedirectUris:
    - "http://localhost:3000/callback"
  allowedScopes:
    - "read"
`,
			);

			const { clientFactory } = createRepositoryFactories();
			const repo = await clientFactory.create({ type: "yaml", path: yamlPath });
			const client = await repo.findById("my-client");

			expect(client).not.toBeNull();
			expect(client?.clientId).toBe("my-client");
			expect(client?.allowedRedirectUris).toEqual(["http://localhost:3000/callback"]);
			expect(client?.allowedScopes).toEqual(["read"]);
		});

		it("refuses a yaml client whose redirect URI query carries a response parameter", async () => {
			const yamlPath = writeYaml(
				"clients.yaml",
				`my-client:
  tokenEndpointAuthMethod: "client_secret_basic"
  clientSecret: "secret123"
  allowedRedirectUris:
    - "https://app.example/cb?iss=x"
`,
			);

			const { clientFactory } = createRepositoryFactories();
			await expect(clientFactory.create({ type: "yaml", path: yamlPath })).rejects.toThrow(
				'allowedRedirectUris[0]: must not carry "iss" in its query',
			);
		});

		it("never quotes a refused redirect URI in the boot error, whose query may carry a credential", async () => {
			const yamlPath = writeYaml(
				"clients-secret.yaml",
				`my-client:
  tokenEndpointAuthMethod: "client_secret_basic"
  clientSecret: "secret123"
  allowedRedirectUris:
    - "https://app.example/cb?token=tok-3f9a&iss=x"
`,
			);
			const { clientFactory } = createRepositoryFactories();
			const refusal = await clientFactory.create({ type: "yaml", path: yamlPath }).then(
				() => undefined,
				(err: unknown) => String((err as Error).message),
			);
			expect(refusal).toContain("allowedRedirectUris[0]");
			expect(refusal).not.toContain("tok-3f9a");
		});

		it("throws AdapterFactoryError for unregistered type", async () => {
			const { clientFactory } = createRepositoryFactories();

			await expect(clientFactory.create({ type: "redis" })).rejects.toBeInstanceOf(
				AdapterFactoryError,
			);
			try {
				await clientFactory.create({ type: "redis" });
			} catch (err) {
				const e = err as AdapterFactoryError;
				expect(e.reason).toBe("unknown");
				expect(e.kind).toBe("ClientRepository");
				expect(e.type).toBe("redis");
				expect(e.registered).toEqual(expect.arrayContaining(["yaml", "static"]));
			}
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

			const { userFactory } = createRepositoryFactories();
			const repo = await userFactory.create({ type: "yaml", path: yamlPath });
			const user = await repo.authenticate("alice", "plainpass");

			expect(user).not.toBeNull();
			expect(user?.username).toBe("alice");
		});

		it("warns user_repository_in_memory once for each repository it builds, under either name, wherever it runs", async () => {
			const yamlPath = writeYaml(
				"users-warned.yaml",
				`alice:
  password: "plainpass"
`,
			);
			const logger = {
				trace: vi.fn(),
				debug: vi.fn(),
				info: vi.fn(),
				warn: vi.fn(),
				error: vi.fn(),
				fatal: vi.fn(),
				child: vi.fn(),
			};
			const { userFactory } = createRepositoryFactories({ logger: logger as unknown as Logger });

			await userFactory.create({ type: "yaml", path: yamlPath });
			await userFactory.create({ type: "yaml", path: yamlPath });
			await userFactory.create({ type: "static", path: yamlPath });

			expect(logger.warn.mock.calls).toEqual([
				[{ store: "userRepository", adapter: "yaml" }, "user_repository_in_memory"],
				[{ store: "userRepository", adapter: "yaml" }, "user_repository_in_memory"],
				[{ store: "userRepository", adapter: "static" }, "user_repository_in_memory"],
			]);
			expect(logger.error).not.toHaveBeenCalled();
		});

		it("refuses a config without a path, under either name, before it warns", async () => {
			const logger = {
				trace: vi.fn(),
				debug: vi.fn(),
				info: vi.fn(),
				warn: vi.fn(),
				error: vi.fn(),
				fatal: vi.fn(),
				child: vi.fn(),
			};
			const { userFactory } = createRepositoryFactories({ logger: logger as unknown as Logger });

			for (const type of ["yaml", "static"]) {
				await expect(userFactory.create({ type })).rejects.toThrow(
					'YAML user repository requires "path" in config',
				);
			}
			expect(logger.warn).not.toHaveBeenCalled();
		});

		it("refuses a users file entry the schema refuses, naming the file, the user and the field and never the value", async () => {
			const body = "39.FBAWt.ck.rbQbPhmLOOPkwFxWEPZEYA3HR07Lr2k5OYqk.vRSi";
			const yamlPath = writeYaml(
				"users-invalid.yaml",
				`alice:
  password: "plainpass"
bob:
  password: "$2b$16$${body}"
`,
			);

			const { userFactory } = createRepositoryFactories();
			const refusal = await userFactory.create({ type: "yaml", path: yamlPath }).then(
				() => undefined,
				(err: unknown) => (err as Error).message,
			);

			expect(refusal).toBe(
				`Invalid entry "bob" in ${yamlPath}: password: the bcrypt cost must be from 04 to 15`,
			);
		});

		it("refuses a users file with an empty username, under either name", async () => {
			const yamlPath = writeYaml(
				"users-empty-name.yaml",
				`"":
  password: "plainpass"
`,
			);

			const { userFactory } = createRepositoryFactories();

			for (const type of ["yaml", "static"]) {
				await expect(userFactory.create({ type, path: yamlPath }), type).rejects.toThrow(
					/username/,
				);
			}
		});

		it("refuses a users file whose bcrypt entries use more than one cost, under either name", async () => {
			const body = "39.FBAWt.ck.rbQbPhmLOOPkwFxWEPZEYA3HR07Lr2k5OYqk.vRSi";
			const yamlPath = writeYaml(
				"users-two-costs.yaml",
				`alice:
  password: "$2b$10$${body}"
bob:
  password: "$2b$12$${body}"
carol:
  password: "plainpass"
`,
			);

			const { userFactory } = createRepositoryFactories();

			for (const type of ["yaml", "static"]) {
				const refusal = await userFactory.create({ type, path: yamlPath }).then(
					() => undefined,
					(err: unknown) => (err as Error).message,
				);
				expect(refusal, type).toMatch(
					/password: bcrypt entries use costs 10 and 12; every bcrypt entry must use one cost/,
				);
				expect(refusal, type).not.toContain(body);
			}
		});

		it("builds a users file whose bcrypt entries share one cost", async () => {
			const body = "39.FBAWt.ck.rbQbPhmLOOPkwFxWEPZEYA3HR07Lr2k5OYqk.vRSi";
			const yamlPath = writeYaml(
				"users-one-cost.yaml",
				`alice:
  password: "$2b$12$${body}"
bob:
  password: "$2y$12$${body}"
carol:
  password: "plainpass"
`,
			);

			const { userFactory } = createRepositoryFactories();
			const repo = await userFactory.create({ type: "yaml", path: yamlPath });

			expect((await repo.authenticate("carol", "plainpass"))?.username).toBe("carol");
		});

		it("refuses a users file in which two users have the same id, naming both users", async () => {
			const yamlPath = writeYaml(
				"users-same-id.yaml",
				`alice:
  password: "a"
  id: "u1"
bob:
  password: "b"
  id: "u1"
`,
			);

			const { userFactory } = createRepositoryFactories();

			await expect(userFactory.create({ type: "yaml", path: yamlPath })).rejects.toThrow(
				/"alice" and "bob"/,
			);
		});

		it("throws AdapterFactoryError for unregistered type", async () => {
			const { userFactory } = createRepositoryFactories();

			await expect(userFactory.create({ type: "http" })).rejects.toBeInstanceOf(
				AdapterFactoryError,
			);
			try {
				await userFactory.create({ type: "http" });
			} catch (err) {
				const e = err as AdapterFactoryError;
				expect(e.reason).toBe("unknown");
				expect(e.kind).toBe("UserRepository");
				expect(e.type).toBe("http");
				expect(e.registered).toEqual(expect.arrayContaining(["yaml", "static"]));
			}
		});
	});

	describe("codeFactory", () => {
		it("creates a code repository from memory config and supports createCode/findByCode", async () => {
			const { codeFactory } = createRepositoryFactories();
			const repo = await codeFactory.create({ type: "memory" });
			const code = await repo.createCode({
				client_id: "test-client",
				redirect_uri: "https://rp.example/cb",
				code_challenge: undefined,
				code_challenge_method: undefined,
				nonce: undefined,
				sid: undefined,
				acr: undefined,
				amr: undefined,
				authentication: undefined,
				grantedScope: undefined,
				grantedAudience: undefined,
			});

			expect(code.code).toBeDefined();
			const fetched = await repo.findByCode(code.code);
			expect(fetched).not.toBeNull();
			expect(fetched?.code).toBe(code.code);
		});

		it("rejects non-numeric defaultExpiresIn", async () => {
			const { codeFactory } = createRepositoryFactories();
			await expect(
				codeFactory.create({ type: "memory", defaultExpiresIn: "not-a-number" }),
			).rejects.toThrow('"defaultExpiresIn" must be a positive whole number of seconds');
		});

		it("rejects Infinity defaultExpiresIn", async () => {
			const { codeFactory } = createRepositoryFactories();
			await expect(
				codeFactory.create({ type: "memory", defaultExpiresIn: Infinity }),
			).rejects.toThrow('"defaultExpiresIn" must be a positive whole number of seconds');
		});

		it("rejects negative defaultExpiresIn", async () => {
			const { codeFactory } = createRepositoryFactories();
			await expect(codeFactory.create({ type: "memory", defaultExpiresIn: -1 })).rejects.toThrow(
				'"defaultExpiresIn" must be a positive whole number of seconds',
			);
		});

		it("rejects a fractional defaultExpiresIn, as the Redis repository does", async () => {
			const { codeFactory } = createRepositoryFactories();
			await expect(codeFactory.create({ type: "memory", defaultExpiresIn: 1.5 })).rejects.toThrow(
				'"defaultExpiresIn" must be a positive whole number of seconds',
			);
		});

		it("refuses an unusable defaultExpiresIn with a RangeError, as the repository's constructor does", async () => {
			const { codeFactory } = createRepositoryFactories();
			for (const defaultExpiresIn of [0, -1, 1.5, Infinity, "not-a-number"]) {
				await expect(
					codeFactory.create({ type: "memory", defaultExpiresIn }),
					String(defaultExpiresIn),
				).rejects.toBeInstanceOf(RangeError);
			}
		});

		it("rejects zero defaultExpiresIn", async () => {
			const { codeFactory } = createRepositoryFactories();
			await expect(codeFactory.create({ type: "memory", defaultExpiresIn: 0 })).rejects.toThrow(
				'"defaultExpiresIn" must be a positive whole number of seconds',
			);
		});

		it("throws AdapterFactoryError for unregistered type", async () => {
			const { codeFactory } = createRepositoryFactories();

			await expect(codeFactory.create({ type: "redis" })).rejects.toBeInstanceOf(
				AdapterFactoryError,
			);
			try {
				await codeFactory.create({ type: "redis" });
			} catch (err) {
				const e = err as AdapterFactoryError;
				expect(e.reason).toBe("unknown");
				expect(e.kind).toBe("CodeRepository");
				expect(e.type).toBe("redis");
				expect(e.registered).toEqual(expect.arrayContaining(["memory"]));
			}
		});
	});
});

describe("createRepositoryFactories — AdapterFactory shape", () => {
	it("returns factories that expose register/create/registeredTypes", () => {
		const { clientFactory, userFactory, codeFactory } = createRepositoryFactories();

		for (const factory of [clientFactory, userFactory, codeFactory]) {
			expect(typeof factory.register).toBe("function");
			expect(typeof factory.create).toBe("function");
			expect(typeof factory.registeredTypes).toBe("function");
		}
	});

	it("pre-registers yaml + static for client/user, memory for code", () => {
		const { clientFactory, userFactory, codeFactory } = createRepositoryFactories();

		expect(clientFactory.registeredTypes().sort()).toEqual(["static", "yaml"]);
		expect(userFactory.registeredTypes().sort()).toEqual(["static", "yaml"]);
		expect(codeFactory.registeredTypes()).toEqual(["memory"]);
	});
});
