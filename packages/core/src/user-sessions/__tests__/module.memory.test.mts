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
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp, defineModule } from "../../index.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "../../jwt/verify.mjs";
import { consoleLogger } from "../../logging/consoleLogger.mjs";
import type { Logger } from "../../logging/Logger.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { memorySessionStoresModule } from "../modules/memory.mjs";
import type { SubjectRevocation } from "../types.mjs";

const minBoot = {
	config: makeValidCoreConfig(),
	pathResolver: (p: string) => p,
} as never;

describe("memorySessionStoresModule", () => {
	it("has the expected manifest shape", () => {
		expect(memorySessionStoresModule.name).toBe("core-session-stores-memory");
		expect(memorySessionStoresModule.requires).toBeUndefined();
		expect(memorySessionStoresModule.provides).toBeDefined();
		const provides = memorySessionStoresModule.provides as Record<string, unknown>;
		expect(typeof provides.userSessionStore).toBe("function");
		expect(typeof provides.sessionRPRegistry).toBe("function");
		expect(typeof provides.sessionFamilyIndex).toBe("function");
		expect(typeof provides.sessionFederationIndex).toBe("function");
		// Bundled here so a single-node deployment gets subject-level
		// revocation by installing the module it already installs.
		expect(typeof provides.subjectSessionIndex).toBe("function");
		expect(typeof provides.subjectRevocation).toBe("function");
		expect(typeof provides.sessionLifecycleStore).toBe("function");
	});

	it("createApp wires all 7 components into ComponentMap", async () => {
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
				"sessionLifecycleStore",
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
		// Without these two slots `revokeAllForSubject` reports both as
		// unavailable and revokes nothing, so the bundle providing them is part
		// of the contract, not an implementation detail.
		expect((components.subjectSessionIndex as { kind: string }).kind).toBe("memory");
		expect((components.subjectRevocation as { kind: string }).kind).toBe("memory");
		expect((components.sessionLifecycleStore as { kind: string }).kind).toBe("memory");

		await handle.dispose();
	});

	describe("its logger reaches the subject revocation store", () => {
		/** Boots the module with `logger` (none when undefined) and answers its subject revocation store. */
		const bootRevocation = async (logger: Logger | undefined) => {
			const activator = defineModule({
				name: "revocation-activator",
				requires: ["subjectRevocation"] as never,
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
				bootstrapComponents: logger === undefined ? minBoot : { ...(minBoot as object), logger },
			} as never);
			const revocation = (handle.components as Record<string, unknown>)
				.subjectRevocation as SubjectRevocation;
			return { handle, revocation };
		};

		const clampedWrite = (revocation: SubjectRevocation) =>
			revocation.revokeBefore(
				"u-1",
				new Date(Date.now() + DEFAULT_CLOCK_SKEW_MS + 60_000),
				new Date(Date.now() + 600_000),
			);

		afterEach(() => {
			vi.restoreAllMocks();
		});

		it("declares the logger as its one optional dependency", () => {
			expect(memorySessionStoresModule.optional).toEqual(["logger"]);
		});

		it("says a clamped boundary on the composition's logger", async () => {
			const warned: string[] = [];
			const logger = {
				trace: () => undefined,
				debug: () => undefined,
				info: () => undefined,
				warn: (_obj: unknown, msg?: string) => {
					if (typeof msg === "string") warned.push(msg);
				},
				error: () => undefined,
				fatal: () => undefined,
				child: () => logger,
			} as unknown as Logger;
			const { handle, revocation } = await bootRevocation(logger);
			await clampedWrite(revocation);
			expect(warned).toContain("subject_revocation_boundary_clamped");
			await handle.dispose();
		});

		it("says it on consoleLogger when the composition has no logger", async () => {
			const warn = vi.spyOn(consoleLogger, "warn").mockImplementation(() => undefined);
			const { handle, revocation } = await bootRevocation(undefined);
			await clampedWrite(revocation);
			expect(warn.mock.calls.map((call) => call[1])).toContain(
				"subject_revocation_boundary_clamped",
			);
			await handle.dispose();
		});
	});
});
