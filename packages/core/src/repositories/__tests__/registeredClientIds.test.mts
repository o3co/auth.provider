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
 * A registered client id that no request can reach is refused at boot.
 *
 * Every route screens a `client_id` with `isWellFormedClientId` before it
 * asks the repository, and refuses one that fails as an unknown client. A
 * client registered under such an id — longer than `MAX_CLIENT_ID_LENGTH`,
 * empty, or carrying a control character — was accepted by the bundled
 * repository and then could never authenticate or authorize: a registration
 * that silently does nothing. So the bundled repository, and the YAML file
 * it is loaded from, refuse it when built, naming the entry's position — not
 * the id, which may carry control characters a terminal would act on.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MAX_CLIENT_ID_LENGTH } from "#/repositories/clientId.mjs";
import { InMemoryClientRepository } from "#/repositories/InMemoryClientRepository.mjs";
import { createRepositoryFactories } from "#/repositories/RepositoryFactory.mjs";

const ENTRY = {
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	clientSecret: "test-secret",
	allowedRedirectUris: ["https://rp.example/cb"],
	allowedScopes: ["read"],
};

const build = (...ids: string[]) =>
	new InMemoryClientRepository(new Map(ids.map((id) => [id, { ...ENTRY }])));

describe("InMemoryClientRepository — a registered client id no request can reach", () => {
	for (const [label, id] of [
		["longer than MAX_CLIENT_ID_LENGTH", "c".repeat(MAX_CLIENT_ID_LENGTH + 1)],
		["empty", ""],
		["carrying a NUL byte", "rp\u0000x"],
		["carrying a line feed", "rp\nx"],
		["carrying a C1 control character", "rp\u0085"],
	] as const) {
		it(`refuses one ${label}, naming its position`, () => {
			expect(() => build("first-app", id)).toThrow(/position 2/);
		});
	}

	it("never repeats an id carrying a control character", () => {
		expect(() => build("rp\u001b[31mx")).toThrow(
			expect.objectContaining({ message: expect.not.stringContaining("\u001b") }),
		);
	});

	it("keeps one at the bound, and finds it", async () => {
		const id = "c".repeat(MAX_CLIENT_ID_LENGTH);
		expect(await build(id).findById(id)).toMatchObject({ clientId: id });
	});
});

describe("the yaml client repository — the same check at boot", () => {
	let tmpDir: string;
	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "registered-client-ids-"));
	});
	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("refuses a file registering an id past MAX_CLIENT_ID_LENGTH", async () => {
		const file = path.join(tmpDir, "clients.yaml");
		fs.writeFileSync(
			file,
			`${"c".repeat(MAX_CLIENT_ID_LENGTH + 1)}:
  tokenEndpointAuthMethod: "client_secret_basic"
  clientSecret: "secret123"
  allowedRedirectUris: ["https://rp.example/cb"]
  allowedScopes: ["read"]
`,
		);
		const { clientFactory } = createRepositoryFactories();
		await expect(clientFactory.create({ type: "yaml", path: file })).rejects.toThrow(/position 1/);
	});
});
