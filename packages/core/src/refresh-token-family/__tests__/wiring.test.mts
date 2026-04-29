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
import type { BootstrapMap } from "../../boot/types.mjs";
import {
	createBootApp,
	createMemoryRefreshTokenFamilyStore,
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenRotationModule,
	defineModule,
	memoryRefreshTokenFamilyStoreModule,
} from "../../index.mjs";

const minBoot = {
	config: {} as never,
	pathResolver: (s: string) => s,
} satisfies Record<string, unknown> as BootstrapMap;

// Activator: same pattern as Phase 5 wiring tests. The boot planner only
// walks `requires` for closure roots (modules with `contributes` or
// `overrides`), so a marker module that contributes a no-op route AND
// requires both wrapper slots forces materialisation. Real downstream
// consumers (oauth grant handlers, logout routes) naturally satisfy this
// via their own route handler modules.
const activatorModule = defineModule({
	name: "test-activate-refresh-token-wrappers",
	requires: ["refreshTokenRotation", "refreshTokenFamilyRevocation"] as const,
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

describe("A3 wiring — happy path with all-memory composition", () => {
	it("createBootApp({ memory store + default rotation + default revocation }) yields working wrappers", async () => {
		const handle = await createBootApp({
			modules: [
				memoryRefreshTokenFamilyStoreModule,
				defaultRefreshTokenRotationModule,
				defaultRefreshTokenFamilyRevocationModule,
				activatorModule,
			],
			bootstrapComponents: minBoot,
		});

		const rotation = (handle.components as { refreshTokenRotation?: unknown })
			.refreshTokenRotation as unknown as {
			register(j: string, f: string, e: Date): Promise<void>;
			rotate(p: string, n: string, f: string, e: Date): Promise<{ outcome: string }>;
		};
		const revocation = (handle.components as { refreshTokenFamilyRevocation?: unknown })
			.refreshTokenFamilyRevocation as unknown as {
			revokeFamily(f: string): Promise<void>;
			isFamilyRevoked(f: string): Promise<boolean>;
		};
		expect(rotation).toBeDefined();
		expect(revocation).toBeDefined();

		await rotation.register("jti-1", "fam-1", new Date(Date.now() + 60_000));
		const rotated = await rotation.rotate("jti-1", "jti-2", "fam-1", new Date(Date.now() + 60_000));
		expect(rotated.outcome).toBe("rotated");

		await revocation.revokeFamily("fam-1");
		expect(await revocation.isFamilyRevoked("fam-1")).toBe(true);

		await handle.dispose();
	});
});

describe("A3 wiring — override path", () => {
	it("custom refreshTokenRotation module REPLACES the default (no duplicate-provides error)", async () => {
		const customRotationModule = defineModule({
			name: "test-custom-rotation",
			requires: ["refreshTokenFamilyStore"] as const,
			provides: {
				refreshTokenRotation: () => ({
					async register() {},
					async rotate() {
						return { outcome: "unknown_family" as const };
					},
				}),
			},
		});

		const handle = await createBootApp({
			modules: [
				memoryRefreshTokenFamilyStoreModule,
				customRotationModule,
				defaultRefreshTokenFamilyRevocationModule,
				activatorModule,
			],
			bootstrapComponents: minBoot,
		});

		const rotation = (handle.components as { refreshTokenRotation?: unknown })
			.refreshTokenRotation as unknown as {
			rotate(p: string, n: string, f: string, e: Date): Promise<{ outcome: string }>;
		};
		const out = await rotation.rotate("a", "b", "c", new Date(Date.now() + 60_000));
		expect(out.outcome).toBe("unknown_family"); // custom impl always returns this

		await handle.dispose();
	});

	it("adding BOTH default and custom refreshTokenRotation modules throws duplicate-provides", async () => {
		const customRotationModule = defineModule({
			name: "test-conflict-rotation",
			requires: ["refreshTokenFamilyStore"] as const,
			provides: {
				refreshTokenRotation: () => ({
					async register() {},
					async rotate() {
						return { outcome: "unknown_family" as const };
					},
				}),
			},
		});

		await expect(
			createBootApp({
				modules: [
					memoryRefreshTokenFamilyStoreModule,
					defaultRefreshTokenRotationModule,
					customRotationModule,
					defaultRefreshTokenFamilyRevocationModule,
				],
				bootstrapComponents: minBoot,
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "duplicate-provides",
		});
	});
});

describe("A3 wiring — direct adapter constructor", () => {
	it("createMemoryRefreshTokenFamilyStore() composes without going through createBootApp", () => {
		const store = createMemoryRefreshTokenFamilyStore();
		expect(store.kind).toBe("memory");
	});
});
