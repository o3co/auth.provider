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
 * `mfaModule` and `mfaModules` through `createApp` (the session-admission
 * ADR's D3, D6, D7; the MFA ADR's D11, D20 and step 3's obligations):
 *
 * - the module requires what its requirement is bound to — `config`, core's
 *   three MFA ports, the user-session store and the requirement resolver —
 *   and reads `auditSink` (under its absence policy) and `logger`;
 * - it registers `sessionRequirements.mfa`, whose reach boot compares with
 *   what the enabled factors reach, and refuses a mismatch;
 * - it keeps, per boot, the object its factory returned — the one core
 *   issued `mfa.step_up` to (step 11's) — and one sealing on the
 *   composition's logger;
 * - it refuses the boot for `mfa.mode = "off"` or unset, for `required` with
 *   no counting factor (`mfa-no-counting-factor`, once the factors have
 *   registered), without a user-session store, for an out-of-range
 *   transaction life or an unusable lock, and without `endpoints.mfa.url`;
 * - it refuses the development sample key outside development, through its
 *   `environment` option, and says once at boot when it accepted it.
 */

import { defineModule, issuedRemediationActions, type MfaFactor } from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it } from "vitest";
import { MFA_DEVELOPMENT_SAMPLE_KEY } from "#/config.mjs";
import { MFA_ROUTES_ID, mfaBootState, mfaModule, mfaModules } from "#/module.mjs";
import { createMfaSealing } from "#/sealing.mjs";
import { mfaTotpFactorModule } from "#/totp/module.mjs";
import {
	boot,
	configFor,
	disposeAll,
	events,
	MFA_KEY,
	mfaSection,
	refusal,
	spyLogger,
} from "./moduleHarness.mjs";
import { stubFactor } from "./requirementHarness.mjs";

afterEach(disposeAll);

/** A module contributing `factor` under its kind. */
const contributing = (factor: MfaFactor) =>
	defineModule({
		name: `test:factor-${factor.kind}`,
		contributes: { mfaFactors: { [factor.kind]: () => factor } },
	});

const TOTP_OFF = {
	factors: { totp: { ...mfaSection("required").factors.totp, enabled: false } },
};

// ---------------------------------------------------------------------------
// What is installed
// ---------------------------------------------------------------------------

describe("mfaModules", () => {
	it("is the TOTP factor's module and the MFA module", () => {
		expect(mfaModules().map((m) => m.name)).toEqual([mfaTotpFactorModule.name, "mfa"]);
		expect(mfaModules()[0]).toBe(mfaTotpFactorModule);
	});

	it("requires what the requirement is bound to, and reads the audit sink — its absence declared — and the logger", () => {
		const module = mfaModule();
		expect([...(module.requires ?? [])].sort()).toEqual(
			[
				"config",
				"mfaFactorResolver",
				"mfaFactorStore",
				"mfaTransactionStore",
				"sessionRequirementResolver",
				"userSessionStore",
			].sort(),
		);
		expect([...(module.optional ?? [])].sort()).toEqual(["auditSink", "logger"]);
		expect(module.absencePolicies?.auditSink).toMatchObject({
			configKey: ["audit", "sink", "type"],
			absentValue: "none",
		});
	});
});

// ---------------------------------------------------------------------------
// The requirement it registers
// ---------------------------------------------------------------------------

describe("the requirement it registers (the session-admission ADR's D3, D7)", () => {
	it("registers mfa with the reach boot recomputes from the enabled factors, the page endpoints.mfa.url names and mfa.step_up — said in the boot line", async () => {
		const { handle, logger } = await boot();
		const registered = handle.components.sessionRequirementResolver?.get("mfa");
		expect([...(registered?.reach ?? [])].sort()).toEqual(["mfa", "otp"]);
		expect(registered?.stepUpPage).toEqual({ url: "/mfa", params: {} });
		expect(registered?.remediations).toEqual(["mfa.step_up"]);
		expect(registered?.hintKeys).toEqual(["enrollable", "email_proof"]);
		const said = logger.info.mock.calls.filter(
			(call) => call[1] === "session_requirements_registered",
		);
		expect(said).toHaveLength(1);
		expect(said[0]?.[0]).toEqual({
			requirements: [{ name: "mfa", module: "mfa", remediations: ["mfa.step_up"] }],
		});
	});

	it("reaches what every enabled factor reaches, another package's among them", async () => {
		const { handle } = await boot({
			extraModules: [contributing(stubFactor("webauthn", ["hwk", "swk"]))],
		});
		expect(
			[...(handle.components.sessionRequirementResolver?.get("mfa")?.reach ?? [])].sort(),
		).toEqual(["hwk", "mfa", "otp", "swk"]);
	});

	it("is refused when its reach is not what the enabled factors reach: core compares the two at the end of the name-keyed pass", async () => {
		// A factor whose amrValues answer core's one read at registration with
		// one list, and every later read — the requirement's — with another.
		let reads = 0;
		const shifty: MfaFactor = {
			...stubFactor("shifty", ["hwk"]),
			get amrValues() {
				reads += 1;
				return reads === 1 ? ["hwk"] : ["hwk", "swk"];
			},
		};
		const err = await refusal({ extraModules: [contributing(shifty)] });
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({ kind: "sessionRequirements", name: "mfa", module: "mfa" });
		expect(String((err.cause as Error).message)).toMatch(
			/reach must be what the installed factors reach/,
		);
	});

	it("keeps, per boot, the object its factory returned — the one core issued mfa.step_up to — and one sealing on the composition's logger", async () => {
		const retired = createMfaSealing({ ring: [{ id: "k-old", key: Buffer.alloc(32, 7) }] });
		const record = { subject: "u-alice", id: "f-1", kind: "totp" };
		const sealed = retired.sealFactorData(record, { lastUsedStep: 1 });
		const { handle, logger } = await boot({
			config: configFor("required", {
				encryptionKeys: [
					{ key: MFA_KEY },
					{ id: "k-old", key: Buffer.alloc(32, 7).toString("base64") },
				],
			}),
		});
		const resolver = handle.components.mfaFactorResolver;
		if (resolver === undefined) throw new Error("no mfaFactorResolver");
		const state = mfaBootState(resolver);
		expect(mfaBootState(resolver)).toBe(state);
		// The object the factory returned, not the copy the resolver answers.
		expect(issuedRemediationActions(state.requirement)?.step_up).toEqual({
			name: "mfa.step_up",
			grade: "remediation",
		});
		expect(
			issuedRemediationActions(handle.components.sessionRequirementResolver?.get("mfa") as never),
		).toBeUndefined();
		// One sealing per boot, on the composition's logger: the retired key is
		// said once however often what it sealed is opened.
		expect(state.sealing.openFactorData(record, sealed)).toMatchObject({ state: "ok" });
		expect(state.sealing.openFactorData(record, sealed)).toMatchObject({ state: "ok" });
		expect(
			events(logger, "info").filter((e) => e === "mfa_factor_sealed_with_retired_key"),
		).toHaveLength(1);
	});

	it("keeps each boot's own: two boots share nothing", async () => {
		const first = await boot();
		const second = await boot();
		const a = first.handle.components.mfaFactorResolver;
		const b = second.handle.components.mfaFactorResolver;
		if (a === undefined || b === undefined) throw new Error("no mfaFactorResolver");
		expect(mfaBootState(a).requirement).not.toBe(mfaBootState(b).requirement);
		expect(mfaBootState(a).sealing).not.toBe(mfaBootState(b).sealing);
	});

	it("contributes its routes' mount, after the session middleware", async () => {
		const { handle } = await boot();
		const ids = handle.routes.map((r) => r.contribution.id);
		expect(ids).toContain(MFA_ROUTES_ID);
		expect(ids.indexOf(MFA_ROUTES_ID)).toBeGreaterThan(ids.indexOf("session-middleware"));
		expect(
			handle.routes.find((r) => r.contribution.id === MFA_ROUTES_ID)?.contribution,
		).toMatchObject({
			mountPath: "/session/mfa",
			after: ["session-middleware"],
		});
	});
});

// ---------------------------------------------------------------------------
// Boot refusals
// ---------------------------------------------------------------------------

describe("the boot refusals (the MFA ADR's D20; the session-admission ADR's D7)", () => {
	it('refuses mfa.mode = "off" with the module installed: remove the module, or set mfa.mode', async () => {
		const err = await refusal({ config: configFor("off") });
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({ kind: "sessionRequirements", name: "mfa", module: "mfa" });
		const message = (err.cause as Error).message;
		expect(message).toContain("mfa.mode");
		expect(message).toMatch(/remove the MFA module, or set mfa\.mode to "required" or "optional"/);
	});

	it("refuses a mode left unset, which reads as off", async () => {
		const err = await refusal({ config: configFor("required", { mode: undefined }) });
		expect(err.reason).toBe("contribute-factory-failed");
		expect((err.cause as Error).message).toMatch(/remove the MFA module/);
	});

	it("refuses required with no counting factor enabled — mfa-no-counting-factor, once the factors have registered — naming the mfa.factors.*.enabled keys", async () => {
		const err = await refusal({ config: configFor("required", TOTP_OFF) });
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({ module: "mfa", kind: "routes" });
		expect(err.cause).toMatchObject({ reason: "mfa-no-counting-factor" });
		const message = (err.cause as Error).message;
		expect(message).toContain("mfa.factors.totp.enabled");
		expect(message).toContain("MFA_TOTP_ENABLED");
	});

	it("refuses required when every enabled factor is one that does not count", async () => {
		const err = await refusal({
			config: configFor("required", TOTP_OFF),
			extraModules: [contributing(stubFactor("recovery_code", ["recovery"], { counting: false }))],
		});
		expect(err.cause).toMatchObject({ reason: "mfa-no-counting-factor" });
	});

	it("accepts required when a counting factor of another package's is the one enabled", async () => {
		await boot({
			config: configFor("required", TOTP_OFF),
			extraModules: [contributing(stubFactor("webauthn", ["hwk", "swk"]))],
		});
	});

	it("boots optional with no counting factor: nobody is asked for one", async () => {
		const { handle } = await boot({ config: configFor("optional", TOTP_OFF) });
		expect(handle.components.sessionRequirementResolver?.get("mfa")?.reach.size).toBe(0);
	});

	it("refuses a composition without a user-session store, naming the slot", async () => {
		const err = await refusal({ userSessionStore: null, withoutLogin: true });
		expect(err.reason).toBe("missing-required-component");
		expect(err.details).toMatchObject({ missingKey: "userSessionStore", rootModule: "mfa" });
	});

	it("refuses an out-of-range transaction life and an unusable lock, naming the key", async () => {
		for (const [mfa, key] of [
			[{ transactionTtlSeconds: 59 }, "mfa.transactionTtlSeconds"],
			[{ transactionTtlSeconds: 1801 }, "mfa.transactionTtlSeconds"],
			[{ maxAttemptsPerTransaction: 0 }, "mfa.maxAttemptsPerTransaction"],
			[{ lockout: { ...mfaSection("required").lockout, threshold: 101 } }, "mfa.lockout.threshold"],
		] as const) {
			const err = await refusal({ config: configFor("required", mfa) });
			expect(err.reason, key).toBe("contribute-factory-failed");
			expect((err.cause as Error).message, key).toContain(key);
		}
	});

	it("refuses a composition without endpoints.mfa.url, the page a step-up starts on, naming it", async () => {
		const config = configFor("required");
		const err = await refusal({
			config: { ...config, endpoints: { ...config.endpoints, mfa: undefined } } as never,
		});
		expect(err.reason).toBe("contribute-factory-failed");
		const message = (err.cause as Error).message;
		expect(message).toContain("endpoints.mfa.url");
		expect(message).toContain("ENDPOINTS_MFA_URL");
	});
});

// ---------------------------------------------------------------------------
// The development sample key
// ---------------------------------------------------------------------------

describe("the development sample key (D11, #473's rule)", () => {
	const sample = () =>
		configFor("required", { encryptionKeys: [{ key: MFA_DEVELOPMENT_SAMPLE_KEY }] });

	it("is refused outside development, through the module's environment", async () => {
		const err = await refusal({ config: sample(), options: { environment: "production" } });
		expect(err.reason).toBe("contribute-factory-failed");
		expect((err.cause as Error).message).toContain("sample key");
	});

	it("is said once at boot when it is accepted — at warn, naming the setting and nothing of the key", async () => {
		const logger = spyLogger();
		await boot({ config: sample(), options: { environment: "development" }, logger });
		const said = logger.warn.mock.calls.filter(
			(call) => call[1] === "mfa_development_sample_key_in_use",
		);
		expect(said).toHaveLength(1);
		expect(JSON.stringify(said[0])).not.toContain(MFA_DEVELOPMENT_SAMPLE_KEY);
		expect(said[0]?.[0]).toMatchObject({ setting: "mfa.encryptionKeys" });
	});

	it("is not said for a key of the deployment's own", async () => {
		const { logger } = await boot();
		expect(events(logger, "warn")).not.toContain("mfa_development_sample_key_in_use");
	});
});
