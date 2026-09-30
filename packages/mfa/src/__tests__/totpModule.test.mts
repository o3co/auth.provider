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
 * `mfaTotpFactorModule` through `createApp` (the MFA ADR's D1, D3, D19): it
 * contributes the `totp` factor under the `mfaFactors` kind, where the
 * coordinator reads it through `mfaFactorResolver`; a factory answering `null`
 * — `mfa-totp-factor.enabled = false` — leaves the kind absent from the
 * resolver. It reads its own section, `mfa-totp-factor`, alone — never the key
 * ring, which a factor never holds — which boot parses with the module's
 * schema before any factory runs; a configuration still setting the section's
 * old path, `mfa.factors.totp`, is refused naming the new one. It registers no
 * session requirement: that is the MFA module's.
 */

import {
	BootError,
	createApp,
	defineModule,
	type MfaFactorResolver,
	type Module,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig, unreadableModuleLeaves } from "@o3co/auth-provider-core/testing";
import { afterEach, describe, expect, it } from "vitest";
import { mfaModule } from "#/module.mjs";
import { encodeBase32 } from "#/totp/base32.mjs";
import { mfaTotpFactorModule } from "#/totp/module.mjs";
import { hotp, totpStep } from "#/totp/rfc6238.mjs";
import { UNSET_RENAMED_VARIABLES } from "./moduleHarness.mjs";

const TOTP = { enabled: true, algorithm: "SHA1", digits: 6, period: 30, window: 1 };

const base = makeValidAppConfig();
/** A configuration whose `mfa-totp-factor` section is `totp`, or which has none, capturing no renamed variable set. */
const configWith = (
	totp: Record<string, unknown> | undefined,
	mfa: Record<string, unknown> = {},
) => ({
	...base,
	oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://login.example" } },
	mfa: { mode: "off", ...mfa },
	...(totp === undefined ? {} : { "mfa-totp-factor": totp }),
	"renamed-variables": UNSET_RENAMED_VARIABLES,
});

/** Reads the resolver as the coordinator will: by requiring it, from a list-shaped contribution. */
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

async function boot(config: Record<string, unknown>) {
	const seen: { resolver?: MfaFactorResolver } = {};
	const handle = await createApp({
		modules: [mfaTotpFactorModule, reader(seen)],
		bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
	});
	disposable = handle;
	return { handle, resolver: seen.resolver };
}

async function bootRefusal(config: Record<string, unknown>): Promise<BootError> {
	try {
		disposable = await createApp({
			modules: [mfaTotpFactorModule, reader({})],
			bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
		});
	} catch (error) {
		expect(error).toBeInstanceOf(BootError);
		return error as BootError;
	}
	throw new Error("expected the boot to be refused");
}

describe("mfaTotpFactorModule", () => {
	it("is a module of its own, stateless, asking only for the config", () => {
		expect(mfaTotpFactorModule.name).toBe("mfa-totp-factor");
		expect(mfaTotpFactorModule.requires).toEqual(["config"]);
		expect(mfaTotpFactorModule.replicaSafety).toBeUndefined();
		expect(Object.keys(mfaTotpFactorModule.contributes ?? {})).toEqual(["mfaFactors"]);
	});

	it("reads its own section at its name, mfa-totp-factor, moved whole from mfa.factors.totp", () => {
		expect(mfaTotpFactorModule.section?.at).toBeUndefined();
		expect(mfaTotpFactorModule.section?.relocatedFrom).toEqual(["mfa.factors.totp"]);
		expect(mfaTotpFactorModule.section?.reference?.href).toMatch(/\/config\/reference\.conf$/);
	});

	it("declares only leaves that read the string an environment variable carries", () => {
		expect(unreadableModuleLeaves([mfaTotpFactorModule, mfaModule()])).toEqual([]);
	});

	it("contributes the totp factor, which the resolver answers by its kind", async () => {
		const { resolver } = await boot(configWith({ ...TOTP }));
		const factor = resolver?.get("totp");
		expect(factor?.kind).toBe("totp");
		expect(factor?.amrValues).toEqual(["otp"]);
		expect([...(resolver?.entries() ?? [])].map(([kind]) => kind)).toEqual(["totp"]);
	});

	it("builds the factor from the configuration: its window, and the issuer from oauth.jwt.issuer", async () => {
		const { resolver } = await boot(configWith({ ...TOTP, window: 0 }));
		const factor = resolver?.get("totp");
		if (factor === undefined) throw new Error("no totp factor");
		const secret = Buffer.from("12345678901234567890", "ascii");
		const nowMs = 1_800_000_000_000;
		const step = totpStep(nowMs, 30);
		const data = {
			secret: encodeBase32(secret),
			algorithm: "SHA1",
			digits: 6,
			period: 30,
			lastUsedStep: 0,
		};
		const verify = (code: string) =>
			factor.verify({
				subject: "u-alice",
				transactionId: "tx-1",
				nowMs,
				request: {},
				digests: {} as never,
				factor: {
					id: "f-1",
					label: undefined,
					createdAt: new Date(0),
					lastUsedAt: undefined,
					data,
				},
				factors: [],
				state: undefined,
				proof: code,
			});
		expect(await verify(hotp(secret, step, { algorithm: "SHA1", digits: 6 }))).toMatchObject({
			ok: true,
		});
		// A window of 0: the previous step's code is not accepted.
		expect(await verify(hotp(secret, step - 1, { algorithm: "SHA1", digits: 6 }))).toEqual({
			ok: false,
			reason: "invalid",
		});
		const begun = await factor.beginEnrollment({
			subject: "u-alice",
			transactionId: "tx-1",
			nowMs,
			request: {},
			digests: {} as never,
			user: { id: "u-alice", username: "alice" },
			factors: [],
		});
		expect((begun.response as { otpauth_uri: string }).otpauth_uri).toMatch(
			/^otpauth:\/\/totp\/login\.example:alice\?/,
		);
	});

	it("leaves the kind absent from the resolver when mfa-totp-factor.enabled is false", async () => {
		const { resolver } = await boot(configWith({ ...TOTP, enabled: "false" }));
		expect(resolver?.get("totp")).toBeUndefined();
		expect([...(resolver?.entries() ?? [])]).toEqual([]);
	});

	it("boots a switched-off factor whatever oauth.jwt.issuer names: the issuer is resolved only for a factor that is on", async () => {
		const noHost = (enabled: unknown) => ({
			...configWith({ ...TOTP, enabled }),
			oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://[2001:db8::1]" } },
		});
		const { resolver } = await boot(noHost(false));
		expect(resolver?.get("totp")).toBeUndefined();
		await disposable?.dispose();
		disposable = undefined;
		const refused = await bootRefusal(noHost(true));
		expect(refused.reason).toBe("contribute-factory-failed");
		expect(refused.message).toContain("mfa-totp-factor.issuer");
		expect(refused.message).toContain("MFA_TOTP_FACTOR_ISSUER");
	});

	it("reads no key ring: the factor never holds a key", async () => {
		const { resolver } = await boot(configWith({ ...TOTP }, { encryptionKeys: [] }));
		expect(resolver?.get("totp")).toBeDefined();
	});

	it("refuses the boot for a section its schema refuses, before any factory runs, naming the key", async () => {
		const refused = await bootRefusal(configWith({ ...TOTP, digits: 9 }));
		expect(refused.reason).toBe("config-validation-failed");
		expect(refused.message).toContain("mfa-totp-factor.digits");
		expect(refused.details).toMatchObject({
			modules: [{ module: "mfa-totp-factor", schemaPath: "mfa-totp-factor" }],
		});
	});

	it("refuses the boot without the package's reference.conf layered beneath the configuration", async () => {
		const refused = await bootRefusal(configWith(undefined));
		expect(refused.reason).toBe("config-validation-failed");
		expect(refused.message).toContain("mfa-totp-factor");
		expect(refused.message).toContain("@o3co/auth-provider-mfa/reference.conf");
	});

	it("refuses a configuration that still sets the old path, naming each key's new path and its variable", async () => {
		const refused = await bootRefusal(
			configWith({ ...TOTP }, { factors: { totp: { enabled: false, issuer: "Example Co" } } }),
		);
		expect(refused.reason).toBe("config-path-relocated");
		expect(refused.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "mfa-totp-factor",
					from: "mfa.factors.totp.enabled",
					to: "mfa-totp-factor.enabled",
					environmentVariable: "MFA_TOTP_FACTOR_ENABLED",
				},
				{
					module: "mfa-totp-factor",
					from: "mfa.factors.totp.issuer",
					to: "mfa-totp-factor.issuer",
					environmentVariable: "MFA_TOTP_FACTOR_ISSUER",
				},
			],
		});
		expect(refused.message).toContain(
			"mfa.factors.totp.enabled has moved to mfa-totp-factor.enabled",
		);
	});

	it("boots over an old path that sets nothing: the empty section an unset variable leaves there", async () => {
		const { resolver } = await boot(configWith({ ...TOTP }, { factors: { totp: {} } }));
		expect(resolver?.get("totp")).toBeDefined();
	});

	it("registers no session requirement", async () => {
		const { handle } = await boot(configWith({ ...TOTP }));
		expect([...(handle.components.sessionRequirementResolver?.entries() ?? [])]).toEqual([]);
		expect(handle.components.sessionRequirementResolver).toBeDefined();
	});
});
