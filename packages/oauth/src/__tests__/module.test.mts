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

import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	GrantRegistry,
	type ModuleContext,
} from "@o3co/auth-provider-core";
import type { Router } from "express";
import { describe, expect, it, vi } from "vitest";
import { oauthModule } from "#/module.mjs";

const mockConfig = {
	oauth: {
		jwt: { secret: "test-secret" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
	endpoints: {
		login: { url: "/login" },
	},
} as unknown as AppConfig;

const makeContext = (overrides?: Partial<ModuleContext>): ModuleContext => ({
	pathResolver: (s: string) => s,
	config: mockConfig,
	keyStore: createSymmetricKeyStore("test-secret"),
	grantRegistry: new GrantRegistry(),
	router: {
		use: vi.fn().mockReturnThis(),
		get: vi.fn().mockReturnThis(),
		post: vi.fn().mockReturnThis(),
	} as unknown as Router,
	...overrides,
});

describe("oauthModule", () => {
	it("has name 'oauth'", () => {
		const module = oauthModule({
			clientRepository: {} as ClientRepository,
			codeRepository: {} as CodeRepository,
		});
		expect(module.name).toBe("oauth");
	});

	it("mounts /oauth routes on context.router", async () => {
		const routerMock = {
			use: vi.fn().mockReturnThis(),
			get: vi.fn().mockReturnThis(),
			post: vi.fn().mockReturnThis(),
		} as unknown as Router;
		const ctx = makeContext({ router: routerMock });
		const module = oauthModule({
			clientRepository: {} as ClientRepository,
			codeRepository: {} as CodeRepository,
		});

		await module.init(ctx);

		// Should have mounted the oauth sub-router on /oauth
		expect((routerMock.use as ReturnType<typeof vi.fn>).mock.calls.length).toBeGreaterThanOrEqual(
			1,
		);
		const oauthCall = (routerMock.use as ReturnType<typeof vi.fn>).mock.calls.find(
			(call: unknown[]) => call[0] === "/oauth",
		);
		expect(oauthCall).toBeDefined();
	});
});
