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
import { describe, expect, it, vi } from "vitest";
import type { Router } from "express";
import { GrantRegistry } from "../../grants/registry.mjs";
import { createSymmetricKeyStore } from "../../keys/KeyStore.mjs";
import type { ModuleContext } from "../types.mjs";
import type { ClientRepository } from "../../repositories/ClientRepository.mjs";
import type { AppConfig } from "../../config/application.schema.mjs";
import { oauthSessionModule } from "../oauthSession.mjs";

const mockConfig = {
	oauth: {
		jwt: { secret: "test-secret" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {
			session: { enabled: true },
		},
	},
} as unknown as AppConfig;

const makeContext = (overrides?: Partial<ModuleContext>): ModuleContext => ({
	pathResolver: (s: string) => s,
	config: mockConfig,
	keyStore: createSymmetricKeyStore("test-secret"),
	grantRegistry: new GrantRegistry(),
	router: { use: vi.fn().mockReturnThis() } as unknown as Router,
	...overrides,
});

describe("oauthSessionModule", () => {
	it("has name 'oauth-session'", () => {
		const module = oauthSessionModule({
			clientRepository: {} as ClientRepository,
		});
		expect(module.name).toBe("oauth-session");
	});

	it("registers session grant handler on grantRegistry", async () => {
		const ctx = makeContext();
		const module = oauthSessionModule({
			clientRepository: {} as ClientRepository,
		});

		await module.init(ctx);

		expect(ctx.grantRegistry.get("session")).toBeDefined();
	});

	it("does not register session grant when config says enabled=false", async () => {
		const disabledConfig = {
			...mockConfig,
			oauth: {
				...mockConfig.oauth,
				grants: { session: { enabled: false } },
			},
		} as unknown as AppConfig;
		const ctx = makeContext({ config: disabledConfig });
		const module = oauthSessionModule({
			clientRepository: {} as ClientRepository,
		});

		await module.init(ctx);

		expect(ctx.grantRegistry.get("session")).toBeUndefined();
	});

	it("registered handler returns 401 for unauthenticated session", async () => {
		const ctx = makeContext();
		const module = oauthSessionModule({
			clientRepository: {} as ClientRepository,
		});

		await module.init(ctx);

		const handler = ctx.grantRegistry.get("session")!;
		const { result } = await handler.handle({
			body: {},
			session: { isAuthenticated: false },
			issuer: "localhost",
			metadata: {},
		});

		expect(result.status).toBe(401);
	});
});
