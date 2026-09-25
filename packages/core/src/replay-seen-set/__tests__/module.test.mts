/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { createApp } from "#/boot/create-app.mjs";
import { BootError, type BootstrapMap } from "#/boot/types.mjs";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { defineModule, type Module } from "#/modules/manifest/index.mjs";
import type { MemoryReplaySeenSet } from "#/replay-seen-set/adapters/memory.mjs";
import { DEFAULT_MEMORY_REPLAY_SEEN_SET_MAX_ENTRIES } from "#/replay-seen-set/adapters/memory.mjs";
import { memoryReplaySeenSetModule } from "#/replay-seen-set/module.mjs";
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
				requires: ["replaySeenSet"] as const,
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

describe("memoryReplaySeenSetModule", () => {
	it("has the canonical module name 'core-replay-seen-set-memory'", () => {
		expect(memoryReplaySeenSetModule.name).toBe("core-replay-seen-set-memory");
	});

	it("provides replaySeenSet via factory, reading its cap from config", () => {
		expect(memoryReplaySeenSetModule.requires ?? []).toEqual(["config"]);
		expect(typeof memoryReplaySeenSetModule.provides?.replaySeenSet).toBe("function");
		const set = memoryReplaySeenSetModule.provides?.replaySeenSet?.({
			config: makeValidCoreConfig(),
		} as never);
		expect((set as { kind: string }).kind).toBe("memory");
	});

	describe("replaySeenSet.memory.maxEntries", () => {
		const seenSetOf = async (extra: Record<string, unknown>): Promise<MemoryReplaySeenSet> => {
			const handle = await bootWith(memoryReplaySeenSetModule, extra);
			const set = handle.components.replaySeenSet as MemoryReplaySeenSet;
			await handle.dispose();
			return set;
		};

		it("survives the schema a composition root parses its config with", () => {
			// `AppConfigSchema` strips what it does not declare, before any module runs.
			const parsed = AppConfigSchema.parse({
				...makeValidAppConfig(),
				replaySeenSet: { memory: { maxEntries: "5000" } },
			});
			expect(parsed.replaySeenSet?.memory?.maxEntries).toBe("5000");
		});

		it("takes the default when the key is absent", async () => {
			expect((await seenSetOf({})).maxEntries).toBe(DEFAULT_MEMORY_REPLAY_SEEN_SET_MAX_ENTRIES);
		});

		it("takes a number, or the string an environment variable delivers", async () => {
			expect(
				(await seenSetOf({ replaySeenSet: { memory: { maxEntries: 5000 } } })).maxEntries,
			).toBe(5000);
			expect(
				(await seenSetOf({ replaySeenSet: { memory: { maxEntries: "7000" } } })).maxEntries,
			).toBe(7000);
		});

		it("refuses a value above what a Map can hold at boot, naming the key", async () => {
			for (const tooMany of [2 ** 24 + 1, "16777217"]) {
				const err = await refusalOf(
					bootWith(memoryReplaySeenSetModule, {
						replaySeenSet: { memory: { maxEntries: tooMany } },
					}),
				);
				expect(err.cause).toBeInstanceOf(RangeError);
				expect((err.cause as Error).message).toBe(
					`replaySeenSet.memory.maxEntries must be at most 16777216, the most entries a Map holds (got ${JSON.stringify(tooMany)})`,
				);
			}
		});

		it("refuses a value it cannot use at boot, naming the key", async () => {
			for (const bad of [0, -1, 1.5, "lots", "", true, null]) {
				const err = await refusalOf(
					bootWith(memoryReplaySeenSetModule, { replaySeenSet: { memory: { maxEntries: bad } } }),
				);
				expect(err.reason, String(bad)).toBe("provides-factory-failed");
				expect(err.cause).toBeInstanceOf(RangeError);
				expect((err.cause as Error).message).toBe(
					`replaySeenSet.memory.maxEntries must be a positive whole number (got ${JSON.stringify(bad)})`,
				);
			}
		});
	});

	it("names what actually forks when it refuses a multi-replica boot", () => {
		// The reason is quoted verbatim into the refused boot message, so it is
		// what an operator reads, and it names exactly what records here:
		// `private_key_jwt` client assertions, the WebAuthn challenge ceremony
		// (a consumed challenge is marked seen), DPoP, which records every proof
		// it accepts, and the jwt-bearer registry verifier for an ID-JAG only —
		// a plain RFC 7523 assertion's `jti` is never recorded, so "a jwt-bearer
		// assertion" would name something that does not fork. DPoP is named as
		// conditional on being enabled: an operator with no DPoP module must
		// not read DPoP as why their boot failed.
		const reason = memoryReplaySeenSetModule.replicaSafety?.unsafe
			? memoryReplaySeenSetModule.replicaSafety.reason
			: "";
		expect(reason).toMatch(/a private_key_jwt client assertion/);
		expect(reason).toMatch(/the jti of an ID-JAG \(jwt-bearer\) assertion/);
		expect(reason).not.toMatch(/, a jwt-bearer assertion/);
		expect(reason).toMatch(/a consumed WebAuthn challenge/);
		expect(reason).toMatch(/with DPoP enabled, a DPoP proof/);
	});
});
