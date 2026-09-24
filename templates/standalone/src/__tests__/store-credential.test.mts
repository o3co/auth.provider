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
 * The credential auth.provider presents to the Store, through the shipped
 * composition: `CLIENT_USER_BEARER_TOKEN` in the environment → the HOCON
 * layers → `AppConfigSchema` → the production `repositoriesModule` → the
 * `"http"` user adapter → the `Authorization` header a real `node:http` Store
 * receives. Unset, the Store receives no `Authorization` header; set blank —
 * an exported-but-empty variable — the user repository is refused.
 */

import { createServer, type Server } from "node:http";
import { fileURLToPath } from "node:url";
import { type AppConfig, AppConfigSchema, type UserRepository } from "@o3co/auth-provider-core";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { afterEach, describe, expect, it } from "vitest";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "../configPath.mjs";
import { repositoriesModule } from "../modules.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

/** 32 bytes of key material — what `openssl rand -hex 32` prints. */
const TOKEN = "7d1f0c3b9a5e2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c3e5b7d9f2a4c6e8b0d1f";

let servers: Server[] = [];
afterEach(async () => {
	await Promise.all(
		servers.map((server) => {
			server.closeAllConnections();
			return new Promise<void>((resolve) => server.close(() => resolve()));
		}),
	);
	servers = [];
});

/** A Store on its own loopback port that records each request's Authorization header. */
const recordingStore = async (): Promise<{ origin: string; heard: (string | undefined)[] }> => {
	const heard: (string | undefined)[] = [];
	const server = createServer((req, res) => {
		req.resume();
		req.on("end", () => {
			heard.push(req.headers.authorization);
			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ id: "user-1", username: "alice" }));
		});
	});
	servers.push(server);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as { port: number };
	return { origin: `http://127.0.0.1:${port}`, heard };
};

/** The shipped config for the production overlay, resolved against `env`. */
const resolve = (env: Record<string, string>): AppConfig => {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	return validate(
		parseFile(envConfPath, { env })
			.withFallback(parseFile(applicationConfPath, { env }))
			.withFallback(parseFile(resolveLibraryReferenceConfPath(), { env })),
		AppConfigSchema,
	);
};

/** The user repository the production `repositoriesModule` builds from `config`. */
const userRepositoryFrom = (config: AppConfig): Promise<UserRepository> =>
	Promise.resolve(
		repositoriesModule.provides?.userRepository?.({ config } as never) as
			| UserRepository
			| Promise<UserRepository>,
	);

const envFor = (origin: string): Record<string, string> => ({
	OAUTH_JWT_ALGORITHM: "HS256",
	OAUTH_JWT_SECRET: "store-credential-composition.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "store-credential-composition-session.at-least-32-bytes.ok",
	CLIENT_USER_TYPE: "http",
	CLIENT_USER_AUTHENTICATE_URL: `${origin}/authenticate`,
	CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL: `${origin}/authenticate-by-token`,
});

describe("CLIENT_USER_BEARER_TOKEN reaches the Store through the shipped composition", () => {
	it("sends Authorization: Bearer <token> on every Store call when the variable is set", async () => {
		const { origin, heard } = await recordingStore();
		const repo = await userRepositoryFrom(
			resolve({ ...envFor(origin), CLIENT_USER_BEARER_TOKEN: TOKEN }),
		);

		await repo.authenticate("alice", "pass");
		await repo.authenticateByToken("apple:a1");

		expect(heard).toEqual([`Bearer ${TOKEN}`, `Bearer ${TOKEN}`]);
	});

	it("sends no Authorization header when the variable is unset", async () => {
		const { origin, heard } = await recordingStore();
		const repo = await userRepositoryFrom(resolve(envFor(origin)));

		await repo.authenticate("alice", "pass");

		expect(heard).toEqual([undefined]);
	});

	it("refuses the user repository when the variable is exported but empty", async () => {
		const { origin, heard } = await recordingStore();
		const config = resolve({ ...envFor(origin), CLIENT_USER_BEARER_TOKEN: "" });

		await expect(userRepositoryFrom(config)).rejects.toThrow(/"bearerToken" must not be empty/);
		expect(heard).toEqual([]);
	});
});
