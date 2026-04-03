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

import { createSymmetricKeyStore } from "../../keys/KeyStore.mjs";
import { GrantRegistry } from "../registry.mjs";
import type {
	GrantDependencies,
	GrantFactory,
	GrantHandler,
	GrantModule,
} from "../types.mjs";

const makeHandler = (name: string): GrantHandler => ({
	handle: vi.fn().mockResolvedValue({
		result: { status: 200, tokens: {} },
	}),
	cleanup: vi.fn(),
});

const makeFactory = (name: string): GrantFactory => {
	return (_deps: GrantDependencies) => makeHandler(name);
};

const makeDeps = (
	grantOverrides: Record<string, { enabled?: boolean }> = {},
): GrantDependencies => ({
	config: {
		oauth: {
			jwt: { secret: "test-secret" },
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400 },
			grants: grantOverrides,
		},
	} as unknown as GrantDependencies["config"],
	keyStore: createSymmetricKeyStore("test-secret"),
});

describe("GrantRegistry.addModule", () => {
	it("registers enabled grants from a module", () => {
		const registry = new GrantRegistry();
		const module: GrantModule = {
			grants: {
				session: makeFactory("session"),
			},
		};
		const deps = makeDeps({ session: { enabled: true } });

		registry.addModule(module, deps);

		expect(registry.get("session")).toBeDefined();
	});

	it("skips grants where config.enabled is false", () => {
		const registry = new GrantRegistry();
		const module: GrantModule = {
			grants: {
				session: makeFactory("session"),
			},
		};
		const deps = makeDeps({ session: { enabled: false } });

		registry.addModule(module, deps);

		expect(registry.get("session")).toBeUndefined();
	});

	it("registers grants with no config entry (treated as enabled)", () => {
		const registry = new GrantRegistry();
		const module: GrantModule = {
			grants: {
				session: makeFactory("session"),
			},
		};
		const deps = makeDeps({}); // no session entry at all

		registry.addModule(module, deps);

		expect(registry.get("session")).toBeDefined();
	});

	it("registers multiple grants from a single module", () => {
		const registry = new GrantRegistry();
		const module: GrantModule = {
			grants: {
				session: makeFactory("session"),
				authorization: makeFactory("authorization"),
				refresh_token: makeFactory("refresh_token"),
			},
		};
		const deps = makeDeps({
			session: { enabled: true },
			authorization: { enabled: true },
			refresh_token: { enabled: true },
		});

		registry.addModule(module, deps);

		expect(registry.get("session")).toBeDefined();
		expect(registry.get("authorization")).toBeDefined();
		expect(registry.get("refresh_token")).toBeDefined();
	});
});
