/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { BootError } from "../../boot/types.mjs";
import { createApp } from "../../index.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import {
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenFamilyRotationModule,
	memoryRefreshTokenFamilyStoreModule,
} from "../module.mjs";

describe("memoryRefreshTokenFamilyStoreModule", () => {
	it("has the canonical module name 'core-refresh-token-family-store-memory'", () => {
		expect(memoryRefreshTokenFamilyStoreModule.name).toBe("core-refresh-token-family-store-memory");
	});

	it("provides refreshTokenFamilyStore via factory; no requires", () => {
		expect(memoryRefreshTokenFamilyStoreModule.requires ?? []).toEqual([]);
		expect(typeof memoryRefreshTokenFamilyStoreModule.provides?.refreshTokenFamilyStore).toBe(
			"function",
		);
		const store = memoryRefreshTokenFamilyStoreModule.provides?.refreshTokenFamilyStore?.(
			{} as never,
		);
		expect(store).toBeDefined();
	});
});

describe("defaultRefreshTokenFamilyRotationModule", () => {
	it("has the canonical module name 'core-default-refresh-token-family-rotation'", () => {
		expect(defaultRefreshTokenFamilyRotationModule.name).toBe(
			"core-default-refresh-token-family-rotation",
		);
	});

	it("requires refreshTokenFamilyStore and config, and provides refreshTokenFamilyRotation", () => {
		expect(new Set(defaultRefreshTokenFamilyRotationModule.requires ?? [])).toEqual(
			new Set(["refreshTokenFamilyStore", "config"]),
		);
		expect(
			typeof defaultRefreshTokenFamilyRotationModule.provides?.refreshTokenFamilyRotation,
		).toBe("function");
	});
});

describe("defaultRefreshTokenFamilyRevocationModule", () => {
	it("has the canonical module name 'core-default-refresh-token-family-revocation'", () => {
		expect(defaultRefreshTokenFamilyRevocationModule.name).toBe(
			"core-default-refresh-token-family-revocation",
		);
	});

	it("requires refreshTokenFamilyStore and config, and provides refreshTokenFamilyRevocation", () => {
		expect(new Set(defaultRefreshTokenFamilyRevocationModule.requires ?? [])).toEqual(
			new Set(["refreshTokenFamilyStore", "config"]),
		);
		expect(
			typeof defaultRefreshTokenFamilyRevocationModule.provides?.refreshTokenFamilyRevocation,
		).toBe("function");
	});
});

describe("the default family modules, over a configuration that resolves no access-token lifetime", () => {
	/**
	 * What a composition loading no oauth-package module hands boot: core's own
	 * reference sets no `oauth {}`, so nothing resolves the access-token
	 * maximum a revoked family's record is kept for. Each module refuses to be
	 * built (`provides-factory-failed`) rather than keep the record for no
	 * time; an environment string no section schema read is refused the same
	 * way.
	 */
	const configWithOAuth = (oauth?: unknown): Record<string, unknown> => {
		const { oauth: _oauth, ...rest } = makeValidCoreConfig() as Record<string, unknown>;
		return oauth === undefined ? rest : { ...rest, oauth };
	};

	/** A module whose route makes boot materialise `slot`. */
	const requiring = (slot: string) =>
		defineModule({
			name: `requires-${slot}`,
			requires: [slot] as never,
			contributes: {
				routes: [
					{
						mountPath: "/__test_noop__",
						id: `noop-${slot}`,
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					},
				],
			},
		});

	it.each([
		[defaultRefreshTokenFamilyRotationModule, "refreshTokenFamilyRotation"],
		[defaultRefreshTokenFamilyRevocationModule, "refreshTokenFamilyRevocation"],
	] as const)("%#: %s refuses to be built, naming the key", async (module, slot) => {
		for (const oauth of [undefined, { accessToken: { defaultExpiresIn: "3600" } }]) {
			const err = await createApp({
				modules: [memoryRefreshTokenFamilyStoreModule, module, requiring(slot)],
				bootstrapComponents: {
					config: configWithOAuth(oauth),
					pathResolver: (p: string) => p,
				} as never,
			}).then(
				async (handle) => {
					await handle.dispose();
					return undefined;
				},
				(e: unknown) => e,
			);
			expect(err).toBeInstanceOf(BootError);
			expect(err).toMatchObject({ reason: "provides-factory-failed" });
			expect(String((err as BootError).message)).toMatch(/oauth\.accessToken\./);
		}
	});
});
