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
import {
	GrantRegistry,
	createSymmetricKeyStore,
	type ModuleContext,
	type CodeRepository,
	type AppConfig,
} from "@o3co/auth-provider-core";
import { oauthAuthorizationModule } from "#/oauthAuthorization.mjs";

const mockConfig = {
	oauth: {
		jwt: { secret: "test-secret" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {
			authorization: { enabled: true },
			refresh_token: { enabled: true },
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

describe("oauthAuthorizationModule", () => {
	it("has name 'oauth-authorization'", () => {
		const module = oauthAuthorizationModule({
			codeRepository: {} as CodeRepository,
		});
		expect(module.name).toBe("oauth-authorization");
	});

	it("registers authorization and refresh_token grant handlers", async () => {
		const ctx = makeContext();
		const module = oauthAuthorizationModule({
			codeRepository: {} as CodeRepository,
		});

		await module.init(ctx);

		expect(ctx.grantRegistry.get("authorization")).toBeDefined();
		expect(ctx.grantRegistry.get("refresh_token")).toBeDefined();
	});

	it("does not register authorization grant when config says enabled=false", async () => {
		const disabledConfig = {
			...mockConfig,
			oauth: {
				...mockConfig.oauth,
				grants: {
					authorization: { enabled: false },
					refresh_token: { enabled: true },
				},
			},
		} as unknown as AppConfig;
		const ctx = makeContext({ config: disabledConfig });
		const module = oauthAuthorizationModule({
			codeRepository: {} as CodeRepository,
		});

		await module.init(ctx);

		expect(ctx.grantRegistry.get("authorization")).toBeUndefined();
		expect(ctx.grantRegistry.get("refresh_token")).toBeDefined();
	});

	it("registered authorization handler returns 400 for invalid code", async () => {
		const ctx = makeContext();
		const mockCodeRepo = {
			consumeByCode: vi.fn().mockResolvedValue(null),
			createCode: vi.fn(),
		} as unknown as CodeRepository;
		const module = oauthAuthorizationModule({
			codeRepository: mockCodeRepo,
		});

		await module.init(ctx);

		const handler = ctx.grantRegistry.get("authorization")!;
		const { result } = await handler.handle({
			body: { code: "bad-code", client_id: "c1" },
			session: { code: "different-code", code_client_id: "c1" },
			issuer: "localhost",
			metadata: {},
		});

		expect(result.status).toBe(400);
	});
});
