/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { createApp } from "#/boot/create-app.mjs";
import { BootError, type BootstrapMap } from "#/boot/types.mjs";
import type { MemoryChallengeStore } from "#/challenges/adapters/memory.mjs";
import { DEFAULT_MEMORY_CHALLENGE_STORE_MAX_ENTRIES } from "#/challenges/adapters/memory.mjs";
import {
	defaultChallengeCeremonyModule,
	memoryChallengeStoreModule,
} from "#/challenges/module.mjs";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { defineModule, type Module } from "#/modules/manifest/index.mjs";
import { makeValidAppConfig, makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

/**
 * Boots `module` over the core fixture with `extra` merged in at the top,
 * beside a module that reads the slot — a provider nobody reads is never run.
 */
const bootWith = (module: Module, extra: Record<string, unknown>) =>
	createApp({
		modules: [
			module,
			defineModule({
				name: "test:reads-the-slot",
				requires: ["challengeStore"] as const,
				// A contribution is what makes a module a root of the boot's
				// activation: its route reads the slot, so the provider runs.
				contributes: {
					routes: [
						() => ({
							id: "test:reads-the-slot",
							mountPath: "/reads-the-slot",
							handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						}),
					],
				},
			}),
		],
		bootstrapComponents: {
			config: { ...makeValidCoreConfig(), ...extra } as never,
			pathResolver: (s: string) => s,
		} satisfies Record<string, unknown> as BootstrapMap,
	});

/** The BootError a boot must fail with. */
const refusalOf = async (boot: Promise<{ dispose(): Promise<void> }>): Promise<BootError> => {
	const outcome = await boot.then(
		async (handle) => {
			await handle.dispose();
			return undefined;
		},
		(err: unknown) => err,
	);
	expect(outcome).toBeInstanceOf(BootError);
	return outcome as BootError;
};

describe("memoryChallengeStoreModule", () => {
	it("has the canonical module name 'core-challenge-store-memory'", () => {
		expect(memoryChallengeStoreModule.name).toBe("core-challenge-store-memory");
	});

	it("provides challengeStore via factory, reading its cap from config", () => {
		expect(memoryChallengeStoreModule.requires ?? []).toEqual(["config"]);
		expect(typeof memoryChallengeStoreModule.provides?.challengeStore).toBe("function");
		const store = memoryChallengeStoreModule.provides?.challengeStore?.({
			config: makeValidCoreConfig(),
		} as never);
		expect((store as { kind: string }).kind).toBe("memory");
	});

	describe("challengeStore.memory.maxEntries", () => {
		const storeOf = async (extra: Record<string, unknown>): Promise<MemoryChallengeStore> => {
			const handle = await bootWith(memoryChallengeStoreModule, extra);
			const store = handle.components.challengeStore as MemoryChallengeStore;
			await handle.dispose();
			return store;
		};

		it("survives the schema a composition root parses its config with", () => {
			// `AppConfigSchema` strips what it does not declare, before any module runs.
			const parsed = AppConfigSchema.parse({
				...makeValidAppConfig(),
				challengeStore: { memory: { maxEntries: "5000" } },
			});
			expect(parsed.challengeStore?.memory?.maxEntries).toBe("5000");
		});

		it("takes the default when the key is absent", async () => {
			expect((await storeOf({})).maxEntries).toBe(DEFAULT_MEMORY_CHALLENGE_STORE_MAX_ENTRIES);
		});

		it("takes a number, or the string an environment variable delivers", async () => {
			expect((await storeOf({ challengeStore: { memory: { maxEntries: 5000 } } })).maxEntries).toBe(
				5000,
			);
			expect(
				(await storeOf({ challengeStore: { memory: { maxEntries: "7000" } } })).maxEntries,
			).toBe(7000);
		});

		it("refuses a value above what a Map can hold at boot, naming the key", async () => {
			for (const tooMany of [2 ** 24 + 1, "16777217"]) {
				const err = await refusalOf(
					bootWith(memoryChallengeStoreModule, {
						challengeStore: { memory: { maxEntries: tooMany } },
					}),
				);
				expect(err.cause).toBeInstanceOf(RangeError);
				expect((err.cause as Error).message).toBe(
					`challengeStore.memory.maxEntries must be at most 16777216, the most entries a Map holds (got ${JSON.stringify(tooMany)})`,
				);
			}
		});

		it("refuses a value it cannot use at boot, naming the key", async () => {
			for (const bad of [0, -1, 1.5, "lots", "", true, null]) {
				const err = await refusalOf(
					bootWith(memoryChallengeStoreModule, { challengeStore: { memory: { maxEntries: bad } } }),
				);
				expect(err.reason, String(bad)).toBe("provides-factory-failed");
				expect(err.cause).toBeInstanceOf(RangeError);
				expect((err.cause as Error).message).toBe(
					`challengeStore.memory.maxEntries must be a positive whole number (got ${JSON.stringify(bad)})`,
				);
			}
		});
	});
});

describe("defaultChallengeCeremonyModule", () => {
	it("has the canonical module name 'core-default-challenge-ceremony'", () => {
		expect(defaultChallengeCeremonyModule.name).toBe("core-default-challenge-ceremony");
	});

	it("requires both challengeStore and replaySeenSet", () => {
		const reqs = defaultChallengeCeremonyModule.requires ?? [];
		expect(new Set(reqs)).toEqual(new Set(["challengeStore", "replaySeenSet"]));
	});

	it("provides challengeCeremony as a factory of (deps) → ChallengeCeremony", () => {
		expect(typeof defaultChallengeCeremonyModule.provides?.challengeCeremony).toBe("function");
	});
});
