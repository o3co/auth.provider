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
 * `webauthnMfaFactorModule` through `createApp`: it contributes the
 * `webauthn` factor under core's `mfaFactors` kind,
 * built from the relying party the `webauthnConfig` slot holds and its own
 * section, `webauthn-mfa-factor`; a factory answering `null` —
 * `webauthn-mfa-factor.enabled = false`, the reference default — leaves the
 * kind absent from the resolver. The relying party is needed only when the
 * factor is on: on without it, the boot is refused, naming the slot and the
 * keys it is built from; off, the module boots without it. The grant
 * installed alone, with the package's reference layered, names no section
 * ignored.
 */

import { fileURLToPath } from "node:url";
import {
	BootError,
	createApp,
	createSymmetricKeyStore,
	defaultChallengeCeremonyModule,
	defineModule,
	type GrantPolicyHook,
	type MfaFactorResolver,
	type Module,
	memoryChallengeStoreModule,
	memoryReplaySeenSetModule,
	memoryWebAuthnCredentialStoreModule,
} from "@o3co/auth-provider-core";
import { unreadableModuleLeaves } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as entry from "#/index.mjs";
import { webauthnMfaFactorModule } from "#/mfaFactor/module.mjs";
import { webauthnModule } from "#/module.mjs";
import { createTestWebAuthnConfig, webauthnMfaFactorConfigForTests } from "#/testing/index.mjs";
import { makeAppConfig } from "./appConfig.fixture.mjs";

const REFERENCE = fileURLToPath(new URL("../../config/reference.conf", import.meta.url));

const base = makeAppConfig();

/** The configuration with `section` as the `webauthn-mfa-factor` section, or none. */
const configWith = (section: Record<string, unknown> | undefined) => ({
	...base,
	oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://test.example" } },
	...(section === undefined ? {} : { "webauthn-mfa-factor": section }),
});

const RELYING_PARTY = createTestWebAuthnConfig({ rpId: "login.example", rpName: "Login" });

const relyingParty = defineModule({
	name: "test:webauthn-config",
	provides: { webauthnConfig: () => RELYING_PARTY },
});

/** Reads the resolver as the coordinator does: by requiring it. */
function reader(seen: { resolver?: MfaFactorResolver }): Module {
	return defineModule({
		name: "test:mfa-factor-reader",
		requires: ["mfaFactorResolver"] as const,
		contributes: {
			routes: [
				(deps) => {
					seen.resolver = deps.mfaFactorResolver;
					return {
						id: "test-mfa-factor-reader",
						mountPath: "/__test_mfa_factor_reader__",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					};
				},
			],
		},
	});
}

let disposable: { dispose(): Promise<void> } | undefined;
afterEach(async () => {
	await disposable?.dispose();
	disposable = undefined;
});

async function boot(config: Record<string, unknown>, modules: readonly Module[] = [relyingParty]) {
	const seen: { resolver?: MfaFactorResolver } = {};
	const handle = await createApp({
		modules: [webauthnMfaFactorModule, ...modules, reader(seen)],
		bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
	});
	disposable = handle;
	return { handle, resolver: seen.resolver };
}

async function refusal(
	config: Record<string, unknown>,
	modules: readonly Module[] = [relyingParty],
): Promise<BootError> {
	try {
		await boot(config, modules);
	} catch (error) {
		expect(error).toBeInstanceOf(BootError);
		return error as BootError;
	}
	throw new Error("expected the boot to be refused");
}

const ON = webauthnMfaFactorConfigForTests({ enabled: true })["webauthn-mfa-factor"];

describe("webauthnMfaFactorModule", () => {
	it("is a module of its own, stateless, taking the relying party alone, when it is wired, contributing a factor", () => {
		expect(webauthnMfaFactorModule.name).toBe("webauthn-mfa-factor");
		expect(webauthnMfaFactorModule.requires ?? []).toEqual([]);
		expect(webauthnMfaFactorModule.optional).toEqual(["webauthnConfig"]);
		expect(webauthnMfaFactorModule.replicaSafety).toBeUndefined();
		expect(Object.keys(webauthnMfaFactorModule.contributes ?? {})).toEqual(["mfaFactors"]);
	});

	it("reads its own section at its name, with the package's reference.conf", () => {
		expect(webauthnMfaFactorModule.section?.at).toBeUndefined();
		expect(webauthnMfaFactorModule.section?.reference?.href).toBe(
			new URL("../../config/reference.conf", import.meta.url).href,
		);
	});

	it("declares only leaves that read the string an environment variable carries", () => {
		expect(unreadableModuleLeaves([webauthnMfaFactorModule])).toEqual([]);
	});

	it("is on the package's entry", () => {
		expect(entry.webauthnMfaFactorModule).toBe(webauthnMfaFactorModule);
	});

	it("contributes the webauthn factor when its section switches it on, which the resolver answers by its kind", async () => {
		const { resolver } = await boot(configWith(ON));
		const factor = resolver?.get("webauthn");
		expect(factor?.kind).toBe("webauthn");
		expect(factor?.amrValues).toEqual(["hwk", "swk"]);
		expect([...(resolver?.entries() ?? [])].map(([kind]) => kind)).toEqual(["webauthn"]);
	});

	it("builds the factor from the relying party the slot holds and the section's user verification", async () => {
		const { resolver } = await boot(configWith({ ...ON, userVerification: "required" }));
		const factor = resolver?.get("webauthn");
		if (factor === undefined) throw new Error("no webauthn factor");
		const { response } = await factor.beginEnrollment({
			subject: "u-alice",
			transactionId: "tx-1",
			nowMs: Date.now(),
			request: {},
			digests: {} as never,
			user: { id: "u-alice", username: "alice" },
			factors: [],
		});
		expect(response).toMatchObject({
			rp: { id: "login.example", name: "Login" },
			authenticatorSelection: { userVerification: "required", residentKey: "discouraged" },
		});
	});

	it("leaves the kind absent from the resolver when webauthn-mfa-factor.enabled is false", async () => {
		const { resolver } = await boot(configWith({ ...ON, enabled: "false" }));
		expect(resolver?.get("webauthn")).toBeUndefined();
		expect([...(resolver?.entries() ?? [])]).toEqual([]);
	});

	it("refuses the boot when on without the relying party, naming the webauthnConfig slot and the keys it is built from", async () => {
		const refused = await refusal(configWith(ON), []);
		expect(refused.reason).toBe("contribute-factory-failed");
		const said = `${refused.message} ${String((refused as { cause?: unknown }).cause)}`;
		for (const named of ["webauthnConfig", "webauthn.rpId", "webauthn.rpName", "webauthn.origin"]) {
			expect(said).toContain(named);
		}
	});

	it("boots when off without the relying party, and contributes no factor", async () => {
		const { resolver } = await boot(configWith({ ...ON, enabled: false }), []);
		expect(resolver?.get("webauthn")).toBeUndefined();
	});

	it("refuses the boot for a section its schema refuses, before any factory runs, naming the key", async () => {
		const refused = await refusal(configWith({ ...ON, userVerification: "always" }));
		expect(refused.reason).toBe("config-validation-failed");
		expect(refused.message).toContain("webauthn-mfa-factor.userVerification");
	});

	it("refuses the boot without the package's reference.conf layered beneath the configuration", async () => {
		const refused = await refusal(configWith(undefined));
		expect(refused.reason).toBe("config-validation-failed");
		expect(refused.message).toContain("webauthn-mfa-factor");
		expect(refused.message).toContain("@o3co/auth-provider-webauthn/reference.conf");
	});

	it("registers no session requirement", async () => {
		const { handle } = await boot(configWith(ON));
		expect([...(handle.components.sessionRequirementResolver?.entries() ?? [])]).toEqual([]);
	});
});

describe("the factor installed beside the grant's allowCredentialsForKnownUser", () => {
	/** The relying party the grant and the factor share, `allowCredentialsForKnownUser` as given. */
	const relyingPartyWith = (allowCredentialsForKnownUser: boolean): Module =>
		defineModule({
			name: "test:webauthn-config",
			provides: {
				webauthnConfig: () =>
					createTestWebAuthnConfig({
						rpId: "login.example",
						rpName: "Login",
						allowCredentialsForKnownUser,
					}),
			},
		});

	/** The grant's module and what it requires beside the relying party. */
	const grant: readonly Module[] = [
		webauthnModule,
		defineModule({
			name: "test:key-store",
			provides: { keyStore: () => createSymmetricKeyStore("test-secret-at-least-32-chars!!") },
		}),
		defineModule({
			name: "test:grant-policy",
			provides: {
				grantPolicy: (): GrantPolicyHook => ({
					kind: "test",
					evaluate: async () => ({ outcome: "allow" }) as const,
				}),
			},
		}),
		memoryChallengeStoreModule,
		memoryReplaySeenSetModule,
		defaultChallengeCeremonyModule,
		memoryWebAuthnCredentialStoreModule,
	];

	it.each([true, false])(
		"refuses the boot with the flag on, the factor enabled: %s, naming the setting and its variable and quoting no value",
		async (enabled) => {
			const refused = await refusal(configWith({ ...ON, enabled }), [
				relyingPartyWith(true),
				...grant,
			]);
			expect(refused.reason).toBe("contribute-factory-failed");
			const said = `${refused.message} ${String((refused as { cause?: unknown }).cause)}`;
			expect(said).toContain("webauthn.allowCredentialsForKnownUser");
			expect(said).toContain("WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER");
			expect(said).not.toContain("login.example");
		},
	);

	it("declares no module switch (isEnabled), so the refusal still runs with the factor off", () => {
		// Second-factor credentials registered while the factor was on outlive
		// switching it off; a module switched off would run no check at all.
		expect("isEnabled" in (webauthnMfaFactorModule.section ?? {})).toBe(false);
	});

	it("boots the grant with the flag on when the factor is not installed", async () => {
		disposable = await createApp({
			modules: [relyingPartyWith(true), ...grant],
			bootstrapComponents: {
				config: configWith(undefined),
				pathResolver: (p: string) => p,
			} as never,
		});
		expect(disposable).toBeDefined();
	});

	it("boots the factor beside the grant with the flag off, and contributes it", async () => {
		const { resolver } = await boot(configWith(ON), [relyingPartyWith(false), ...grant]);
		expect(resolver?.get("webauthn")).toBeDefined();
	});
});

describe("the grant installed without the factor", () => {
	it("names no section ignored when the package's reference.conf is layered: the factor's section is declared", async () => {
		const reference = parseFile(REFERENCE, { env: {} }).toObject() as Record<string, unknown>;
		const warn = vi.fn();
		const logger = {
			trace: vi.fn(),
			debug: vi.fn(),
			info: vi.fn(),
			warn,
			error: vi.fn(),
			fatal: vi.fn(),
			child: vi.fn(),
		};
		logger.child.mockReturnValue(logger);
		const config = {
			...configWith(undefined),
			...reference,
			"renamed-variables": {
				...(base["renamed-variables"] as Record<string, unknown>),
				...(reference["renamed-variables"] as Record<string, unknown>),
			},
		};
		disposable = await createApp({
			modules: [
				webauthnModule,
				relyingParty,
				defineModule({
					name: "test:key-store",
					provides: { keyStore: () => createSymmetricKeyStore("test-secret-at-least-32-chars!!") },
				}),
				defineModule({
					name: "test:grant-policy",
					provides: {
						grantPolicy: (): GrantPolicyHook => ({
							kind: "test",
							evaluate: async () => ({ outcome: "allow" }) as const,
						}),
					},
				}),
				memoryChallengeStoreModule,
				memoryReplaySeenSetModule,
				defaultChallengeCeremonyModule,
				memoryWebAuthnCredentialStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (p: string) => p, logger } as never,
		});

		expect(reference).toHaveProperty("webauthn-mfa-factor");
		expect(warn.mock.calls.map((call) => call[1])).not.toContain("config_sections_ignored");
	});
});
