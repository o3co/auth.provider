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
import { describe, expect, it } from "vitest";
import { createApp, defineModule } from "../../index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { memorySessionStoresModule } from "../modules/memory.mjs";

const minBoot = {
	config: makeValidCoreConfig(),
	pathResolver: (p: string) => p,
} as never;

describe("memorySessionStoresModule", () => {
	it("has the expected manifest shape", () => {
		expect(memorySessionStoresModule.name).toBe("memorySessionStores");
		expect(memorySessionStoresModule.requires).toBeUndefined();
		expect(memorySessionStoresModule.provides).toBeDefined();
		const provides = memorySessionStoresModule.provides as Record<string, unknown>;
		expect(typeof provides.userSessionStore).toBe("function");
		expect(typeof provides.sessionRPRegistry).toBe("function");
		expect(typeof provides.sessionFamilyIndex).toBe("function");
		expect(typeof provides.sessionFederationIndex).toBe("function");
		// #296 — bundled here so a single-node deployment gets subject-level
		// revocation by installing the module it already installs.
		expect(typeof provides.subjectSessionIndex).toBe("function");
		expect(typeof provides.subjectRevocation).toBe("function");
	});

	it("createApp wires all 6 components into ComponentMap", async () => {
		// Use a no-op route contributor to force the boot planner to materialise
		// the module graph (requires the modules to be active). Components are
		// read from handle.components after boot completes.
		const activator = defineModule({
			name: "activator",
			requires: [
				"userSessionStore",
				"sessionRPRegistry",
				"sessionFamilyIndex",
				"sessionFederationIndex",
				"subjectSessionIndex",
				"subjectRevocation",
			] as never,
			contributes: {
				routes: [
					{
						mountPath: "/__test_noop__",
						id: "test-noop",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					},
				],
			},
		});

		const handle = await createApp({
			modules: [memorySessionStoresModule, activator],
			bootstrapComponents: minBoot,
		});

		const components = handle.components as Record<string, unknown>;
		expect((components.userSessionStore as { kind: string }).kind).toBe("memory");
		expect((components.sessionRPRegistry as { kind: string }).kind).toBe("memory");
		expect((components.sessionFamilyIndex as { kind: string }).kind).toBe("memory");
		expect((components.sessionFederationIndex as { kind: string }).kind).toBe("memory");
		// #296 — without these two slots `revokeAllForSubject` reports both as
		// unavailable and revokes nothing, so the bundle providing them is part
		// of the contract, not an implementation detail.
		expect((components.subjectSessionIndex as { kind: string }).kind).toBe("memory");
		expect((components.subjectRevocation as { kind: string }).kind).toBe("memory");

		await handle.dispose();
	});
});
