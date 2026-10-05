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
 * `webauthn {}`, `webauthnModule`'s own section: parsed at boot with
 * `webauthnConfigSchema` — so the relying party's id and allowed origins are
 * read and refused exactly as that schema reads them — refusing an unknown
 * key at every level, naming its path, with every default from the package's
 * `config/reference.conf`. The module fills the `webauthnConfig` slot from it
 * and names the slot `authoritative`; it reads the issuer's token settings
 * from the `oauthTokenSettings` slot, which it requires.
 */

import { fileURLToPath } from "node:url";
import {
	BootError,
	createApp,
	createSymmetricKeyStore,
	defaultChallengeCeremonyModule,
	defineModule,
	type GrantPolicyHook,
	type Module,
	memoryChallengeStoreModule,
	memoryReplaySeenSetModule,
	memoryWebAuthnCredentialStoreModule,
} from "@o3co/auth-provider-core";
import { sectionStrictnessProblems } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import express from "express";
import supertest from "supertest";
import { describe, expect, it } from "vitest";
import { type WebAuthnConfig, webauthnConfigSchema } from "#/config.mjs";
import { webauthnModule } from "#/module.mjs";
import { makeAppConfig, testTokenSettings, withWebAuthnSection } from "./appConfig.fixture.mjs";

/** The package's defaults, as a composition root finds them. */
const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

/** The three keys the reference cannot default, as an operator sets them. */
const RELYING_PARTY_ENV = {
	WEBAUTHN_RP_ID: "example.com",
	WEBAUTHN_RP_NAME: "Example App",
	WEBAUTHN_ORIGIN: "https://example.com,https://app.example.com",
};

/** The `webauthn` section as the reference resolves under `env`, `overrides` laid over it. */
const shippedSection = (
	env: Readonly<Record<string, string>> = RELYING_PARTY_ENV,
	overrides: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> => ({
	...((
		parseFile(fileURLToPath(REFERENCE), { env: { ...env } }).toObject() as {
			webauthn: Record<string, unknown>;
		}
	).webauthn as Record<string, unknown>),
	...overrides,
});

const ISSUER = makeAppConfig().oauth.jwt.issuer;

const slotsModule = defineModule({
	name: "test:webauthn-section-slots",
	provides: {
		keyStore: () => createSymmetricKeyStore("webauthn-section-secret-32-bytes!!"),
		grantPolicy: (): GrantPolicyHook => ({
			kind: "test-allow",
			evaluate: async () => ({ outcome: "allow" }) as const,
		}),
	},
});

const STORES: readonly Module[] = [
	memoryChallengeStoreModule,
	memoryReplaySeenSetModule,
	defaultChallengeCeremonyModule,
	memoryWebAuthnCredentialStoreModule,
];

/** Boots `webauthnModule` over `section`, with no module of the deployment's filling `webauthnConfig`. */
const boot = (
	section: unknown,
	options: {
		readonly modules?: readonly Module[];
		readonly bootstrap?: Record<string, unknown>;
		readonly overrides?: Record<string, unknown>;
		readonly withoutTokenSettings?: boolean;
	} = {},
) =>
	createApp({
		modules: [webauthnModule, slotsModule, ...STORES, ...(options.modules ?? [])],
		bootstrapComponents: {
			config: withWebAuthnSection(makeAppConfig(), section),
			pathResolver: (p: string) => p,
			...(options.withoutTokenSettings === true
				? {}
				: { oauthTokenSettings: testTokenSettings({ issuer: ISSUER }) }),
			...options.bootstrap,
		} as never,
		...(options.overrides === undefined ? {} : { overrideComponents: options.overrides as never }),
	});

const refusal = async (promise: Promise<{ dispose(): Promise<void> }>): Promise<BootError> => {
	const outcome = await promise.then(
		async (handle) => {
			await handle.dispose();
			return undefined;
		},
		(error: unknown) => error,
	);
	if (!(outcome instanceof BootError)) throw new Error(`expected a BootError, got ${outcome}`);
	return outcome;
};

describe("the webauthn section", () => {
	it("is parsed with webauthnConfigSchema, so the relying party is read and refused as that schema reads it", () => {
		expect(webauthnModule.section?.schema).toBe(webauthnConfigSchema);
	});

	it("resolves every default but the relying party from the package's reference.conf", () => {
		expect(webauthnConfigSchema.parse(shippedSection())).toStrictEqual({
			rpId: "example.com",
			rpName: "Example App",
			origin: ["https://example.com", "https://app.example.com"],
			challengeTtlMs: 120_000,
			attestationPreference: "none",
			userVerification: "preferred",
			rateLimit: { authenticationOptions: { limit: 30, windowSeconds: 60 } },
		});
	});

	it("refuses an unknown key at every level of the section, naming its path", () => {
		expect(
			sectionStrictnessProblems([webauthnModule], {
				samples: { webauthn: [shippedSection()] },
			}),
		).toEqual([]);
		const refusedPaths = (section: unknown): string[] =>
			(webauthnConfigSchema.safeParse(section).error?.issues ?? []).map((issue) =>
				issue.path.map(String).join("."),
			);
		expect(refusedPaths(shippedSection(undefined, { typo: 1 }))).toEqual([""]);
		expect(
			refusedPaths(
				shippedSection(undefined, {
					rateLimit: { authenticationOptions: { limit: 30, windowSeconds: 60 }, typo: 1 },
				}),
			),
		).toEqual(["rateLimit"]);
		expect(
			refusedPaths(
				shippedSection(undefined, {
					rateLimit: { authenticationOptions: { limit: 30, windowSeconds: 60, burst: 5 } },
				}),
			),
		).toEqual(["rateLimit.authenticationOptions"]);
	});

	it.each([
		["webauthn", { typo: 1 }],
		[
			"webauthn.rateLimit",
			{ rateLimit: { authenticationOptions: { limit: 30, windowSeconds: 60 }, typo: 1 } },
		],
		[
			"webauthn.rateLimit.authenticationOptions",
			{ rateLimit: { authenticationOptions: { limit: 30, windowSeconds: 60, burst: 5 } } },
		],
	])("refuses the boot for an unknown key at %s, naming the path", async (path, overrides) => {
		const error = await refusal(boot(shippedSection(undefined, overrides)));
		expect(error.reason).toBe("config-validation-failed");
		expect(error.message).toContain(path);
	});

	it("refuses the boot without a relying party, naming each key the reference cannot default", async () => {
		const error = await refusal(boot(shippedSection({})));
		expect(error.reason).toBe("config-validation-failed");
		for (const key of ["webauthn.rpId", "webauthn.rpName", "webauthn.origin"]) {
			expect(error.message).toContain(key);
		}
	});

	it("refuses the boot for an origin webauthnConfigSchema refuses, in its words", async () => {
		const error = await refusal(
			boot(shippedSection({ ...RELYING_PARTY_ENV, WEBAUTHN_ORIGIN: "https://example.com/" })),
		);
		expect(error.reason).toBe("config-validation-failed");
		expect(error.message).toContain("webauthn.origin.0");
		const own = webauthnConfigSchema.safeParse(
			shippedSection({ ...RELYING_PARTY_ENV, WEBAUTHN_ORIGIN: "https://example.com/" }),
		).error?.issues[0]?.message;
		expect(own).toBeDefined();
		expect(error.message).toContain(own as string);
	});
});

describe("the webauthnConfig slot", () => {
	it("is provided by webauthnModule from its section, and named authoritative", () => {
		expect(webauthnModule.requires).not.toContain("webauthnConfig");
		expect(webauthnModule.optional).not.toContain("webauthnConfig");
		expect(Object.keys(webauthnModule.provides ?? {})).toEqual(["webauthnConfig"]);
		expect(webauthnModule.authoritative).toEqual(["webauthnConfig"]);
	});

	it("holds the section as parsed for a module that reads it, with no module of the deployment's filling it", async () => {
		let read: unknown;
		const reader = defineModule({
			name: "test:webauthn-config-reader",
			requires: ["webauthnConfig"] as const,
			contributes: {
				routes: [
					({ webauthnConfig }) => {
						read = webauthnConfig;
						return {
							id: "test-webauthn-config-reader",
							mountPath: "/__test_webauthn_config_reader__",
							handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						};
					},
				],
			},
		});
		const handle = await boot(shippedSection(), { modules: [reader] });
		try {
			expect(read).toStrictEqual(webauthnConfigSchema.parse(shippedSection()));
			// The routes run on the section too.
			const app = express();
			app.use(handle.router);
			const res = await supertest(app)
				.post("/oauth/webauthn/authentication/options")
				.set("Content-Type", "application/json")
				.send("{}");
			expect(res.status).toBe(200);
			expect(res.body.rpId).toBe("example.com");
		} finally {
			await handle.dispose();
		}
	});

	it("refuses a deployment module providing it beside webauthnModule (duplicate-provides)", async () => {
		const bridge = defineModule({
			name: "deployment:webauthn-config",
			provides: {
				webauthnConfig: (): WebAuthnConfig => webauthnConfigSchema.parse(shippedSection()),
			},
		});
		const error = await refusal(boot(shippedSection(), { modules: [bridge] }));
		expect(error.reason).toBe("duplicate-provides");
		expect(error.message).toContain("webauthnConfig");
	});

	it("refuses it in bootstrapComponents while webauthnModule is loaded (bootstrap-component-collision)", async () => {
		const error = await refusal(
			boot(shippedSection(), {
				bootstrap: { webauthnConfig: webauthnConfigSchema.parse(shippedSection()) },
			}),
		);
		expect(error.reason).toBe("bootstrap-component-collision");
		expect(error.message).toContain("webauthnConfig");
	});

	it("refuses an overrideComponents entry for it while webauthnModule is loaded (authoritative-component-overridden)", async () => {
		const error = await refusal(
			boot(shippedSection(), {
				overrides: { webauthnConfig: webauthnConfigSchema.parse(shippedSection()) },
			}),
		);
		expect(error.reason).toBe("authoritative-component-overridden");
	});
});

describe("the oauthTokenSettings slot", () => {
	it("is required, and the whole configuration's oauth keys are not read", () => {
		expect(webauthnModule.requires).toContain("oauthTokenSettings");
		expect(webauthnModule.optional).not.toContain("oauthTokenSettings");
	});

	it("refuses the boot without it, naming the slot", async () => {
		const error = await refusal(boot(shippedSection(), { withoutTokenSettings: true }));
		expect(error.reason).toBe("missing-required-component");
		expect(error.message).toContain("oauthTokenSettings");
	});
});
