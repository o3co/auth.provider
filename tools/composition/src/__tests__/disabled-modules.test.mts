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

/**
 * Every module with an `enabled` key of its own, switched off by it,
 * registers nothing: it is switched off by its section (`section.isEnabled`,
 * which core reads to register nothing of it), or it is built from a
 * configuration that switches it off and declares nothing but its section.
 * Booted alone, each boots with none of what it would require, and contributes
 * no route, grant or factor. Each section comes from its package's own published
 * defaults (its `reference.conf`) or the package's testing builder.
 */

import { fileURLToPath } from "node:url";
import { type BootstrapMap, createApp, type Module } from "@o3co/auth-provider-core";
import {
	CORE_RELOCATIONS,
	makeValidCoreConfig,
	renamedVariableCaptures,
} from "@o3co/auth-provider-core/testing";
import { deviceGrantModule } from "@o3co/auth-provider-device-grant";
import { dpopModule } from "@o3co/auth-provider-dpop";
import { federationGrantsModule } from "@o3co/auth-provider-federation-grants";
import {
	mfaEmailFactorModule,
	mfaRecoveryCodeFactorModule,
	mfaTotpFactorModule,
} from "@o3co/auth-provider-mfa";
import {
	mfaEmailFactorConfigForTests,
	mfaRecoveryCodeFactorConfigForTests,
	mfaTotpFactorConfigForTests,
} from "@o3co/auth-provider-mfa/testing";
import { mtlsModule } from "@o3co/auth-provider-mtls";
import { oauthSessionModule } from "@o3co/auth-provider-oauth";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";

/** A module's own section as its package's `reference.conf` ships it. */
const shipped = (module: Module): Record<string, unknown> => {
	const reference = module.section?.reference;
	if (reference === undefined) throw new Error(`${module.name} declares no reference.conf`);
	const tree = parseFile(fileURLToPath(reference), { env: {} }).toObject() as Record<
		string,
		unknown
	>;
	return { [module.name]: tree[module.name] };
};

/** The configuration a disabled module boots in: core's, with its own section. */
type Case = readonly [
	name: string,
	section: () => Record<string, unknown>,
	build: (config: unknown) => Module,
];

const CASES: readonly Case[] = [
	["dpop", () => shipped(dpopModule), () => dpopModule],
	["mtls", () => shipped(mtlsModule), () => mtlsModule],
	[
		"device-grant",
		() => shipped(deviceGrantModule({ config: makeValidCoreConfig() as never })),
		(config) => deviceGrantModule({ config: config as never }),
	],
	[
		"oauth-session",
		() => shipped(oauthSessionModule({ config: makeValidCoreConfig() as never })),
		(config) => oauthSessionModule({ config: config as never }),
	],
	["federation-grants", () => shipped(federationGrantsModule), () => federationGrantsModule],
	[
		"mfa-totp-factor",
		() => mfaTotpFactorConfigForTests({ enabled: false }),
		() => mfaTotpFactorModule,
	],
	[
		"mfa-recovery-code-factor",
		() => mfaRecoveryCodeFactorConfigForTests({ enabled: false }),
		() => mfaRecoveryCodeFactorModule,
	],
	[
		"mfa-email-factor",
		() => mfaEmailFactorConfigForTests({ enabled: false }),
		() => mfaEmailFactorModule,
	],
];

const configWith = (section: Record<string, unknown>) => ({ ...makeValidCoreConfig(), ...section });

/** What a manifest declares beyond its name and its section. */
const declaredBeyondSection = (module: Module): string[] =>
	Object.keys(module).filter((key) => key !== "name" && key !== "section");

describe("a module its own enabled key switches off", () => {
	it.each(CASES)("%s registers nothing", (name, section, build) => {
		const written = section();
		const module = build(configWith(written));
		expect(module.name).toBe(name);
		expect((written[name] as { enabled?: unknown } | undefined)?.enabled).toBe(false);
		const isEnabled = module.section?.isEnabled;
		if (isEnabled === undefined) {
			expect(declaredBeyondSection(module)).toEqual([]);
			return;
		}
		expect(isEnabled.call(module.section, module.section?.schema.parse(written[name]))).toBe(false);
		expect(
			isEnabled.call(
				module.section,
				module.section?.schema.parse({ ...(written[name] as object), enabled: true }),
			),
		).toBe(true);
	});

	it.each(CASES)(
		"%s boots alone, with none of what it would require, and contributes no route, grant or factor",
		async (name, section, build) => {
			const written = configWith(section());
			const module = build(written);
			const config = {
				...written,
				"renamed-variables": renamedVariableCaptures({
					modules: [module],
					core: CORE_RELOCATIONS,
					env: {},
				}),
			};
			const handle = await createApp({
				modules: [module],
				bootstrapComponents: { config, pathResolver: (s: string) => s } as unknown as BootstrapMap,
			});
			try {
				expect(handle.routes.filter((route) => route.contributedBy === name)).toEqual([]);
				expect([...(handle.components.grantHandlerResolver?.entries() ?? [])]).toEqual([]);
				expect([...(handle.components.mfaFactorResolver?.entries() ?? [])]).toEqual([]);
			} finally {
				await handle.dispose();
			}
		},
	);
});
