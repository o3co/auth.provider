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
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import type { BootstrapMap } from "../../boot/types.mjs";
import {
	createBootApp,
	createMemoryChallengeStore,
	createMemoryReplaySeenSet,
	defaultChallengeCeremonyModule,
	defineModule,
	memoryChallengeStoreModule,
	memoryReplaySeenSetModule,
} from "../../index.mjs";

// Per ADR 2026-04-30: schema is a pure type contract; defaults live in
// hocon. validateAndComposeConfig calls CoreConfigSchema.parse, so the
// fixture supplies a minimal schema-valid baseline (intentionally
// diverges from application.conf — see makeValidCoreConfig docstring).
const minBoot = {
	config: makeValidCoreConfig() as never,
	pathResolver: (s: string) => s,
} satisfies Record<string, unknown> as BootstrapMap;

// Activator: a real downstream consumer would naturally activate `challengeCeremony`
// via a route handler module that requires it. In these wiring tests there is no
// such handler, so we add a marker module that contributes a no-op route AND
// requires `challengeCeremony`. The boot planner only walks `requires` for
// closure roots — modules that contribute or override. A bare `requires`-only
// module would be ignored.
const activateCeremonyModule = defineModule({
	name: "test-activate-ceremony",
	requires: ["challengeCeremony"] as const,
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

describe("A1 wiring — happy path with all-memory composition", () => {
	it("createBootApp({ memory store + memory set + default ceremony }) yields a working ceremony", async () => {
		const handle = await createBootApp({
			modules: [
				memoryChallengeStoreModule,
				memoryReplaySeenSetModule,
				defaultChallengeCeremonyModule,
				activateCeremonyModule,
			],
			bootstrapComponents: minBoot,
		});

		const ceremony = (handle.components as { challengeCeremony?: { consume: typeof Function } })
			.challengeCeremony;
		expect(ceremony).toBeDefined();

		const outcome = await (
			ceremony as unknown as {
				consume: (s: string, v: string) => Promise<{ outcome: string }>;
			}
		).consume("scope-A", "value-1");
		expect(outcome.outcome).toBe("unknown");

		await handle.dispose();
	});
});

describe("A1 wiring — override path", () => {
	it("custom challengeCeremony module REPLACES the default (no duplicate-provides error)", async () => {
		const customCeremonyModule = defineModule({
			name: "test-custom-ceremony",
			requires: ["challengeStore", "replaySeenSet"] as const,
			provides: {
				challengeCeremony: () => ({
					consume: async () => ({ outcome: "consumed" as const }),
				}),
			},
		});

		const handle = await createBootApp({
			modules: [
				memoryChallengeStoreModule,
				memoryReplaySeenSetModule,
				customCeremonyModule,
				activateCeremonyModule,
			],
			bootstrapComponents: minBoot,
		});
		const ceremony = (handle.components as { challengeCeremony?: { consume: typeof Function } })
			.challengeCeremony;
		const outcome = await (
			ceremony as unknown as {
				consume: (s: string, v: string) => Promise<{ outcome: string }>;
			}
		).consume("scope-A", "anything");
		expect(outcome.outcome).toBe("consumed");
		await handle.dispose();
	});

	it("adding BOTH defaultChallengeCeremonyModule AND a custom challengeCeremony module throws BootError reason 'duplicate-provides'", async () => {
		const customCeremonyModule = defineModule({
			name: "test-conflict-ceremony",
			requires: ["challengeStore", "replaySeenSet"] as const,
			provides: {
				challengeCeremony: () => ({
					consume: async () => ({ outcome: "unknown" as const }),
				}),
			},
		});

		await expect(
			createBootApp({
				modules: [
					memoryChallengeStoreModule,
					memoryReplaySeenSetModule,
					defaultChallengeCeremonyModule,
					customCeremonyModule,
				],
				bootstrapComponents: minBoot,
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "duplicate-provides",
		});
	});
});

describe("A1 wiring — direct adapter constructors (without modules)", () => {
	it("createMemoryChallengeStore() + createMemoryReplaySeenSet() compose without going through createBootApp", () => {
		const store = createMemoryChallengeStore();
		const set = createMemoryReplaySeenSet();
		expect(store.kind).toBe("memory");
		expect(set.kind).toBe("memory");
	});
});
