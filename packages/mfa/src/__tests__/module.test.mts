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
 * `mfaModule` and `mfaModules` through `createApp`: what the module requires
 * and reads, the requirement it registers, what it keeps per boot, the boots
 * it refuses and the development sample key; each case's name states its
 * rule. See ADR 2026-09-28-session-admission and ADR
 * 2026-09-25-multi-factor-authentication.
 */

import {
	ADMISSION_ACTIONS,
	type AppConfig,
	admitPrimary,
	createInMemoryUserSessionStore,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type DeploymentMode,
	defineModule,
	issuedRemediationActions,
	type MfaFactor,
	passwordPrimary,
	passwordSessionAuthentication,
	readAcrTable,
	requirementSession,
	type SessionRequirement,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestOAuthTokenSettings, resolverForTests } from "@o3co/auth-provider-core/testing";
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
				"deploymentMode",
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

describe("the requirement it registers", () => {
	it("registers mfa with the reach boot recomputes from the enabled factors, the page endpoints.mfa.url names and mfa.step_up — said in the boot line", async () => {
		const { handle, logger } = await boot();
		const registered = handle.components.sessionRequirementResolver?.get("mfa");
		expect([...(registered?.reach ?? [])].sort()).toEqual(["mfa", "otp"]);
		// Resolved at registration on the configuration's issuer.
		expect(registered?.stepUpPage).toEqual({
			url: "/mfa",
			params: {},
			href: "https://auth.example/mfa",
		});
		expect(registered?.remediations).toEqual(["mfa.step_up"]);
		expect(registered?.hintKeys).toEqual(["enrollable", "email_proof"]);
		const said = logger.info.mock.calls.filter(
			(call) => call[1] === "session_requirements_registered",
		);
		expect(said).toHaveLength(1);
		expect(said[0]?.[0]).toEqual({
			requirements: [
				{ name: "mfa", module: "mfa", remediations: ["mfa.step_up"], secondFactorAuthority: true },
			],
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

describe("the boot refusals", () => {
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

	it("refuses required with no counting factor enabled — mfa-no-counting-factor, once the factors have registered — telling the operator to enable an installed counting factor's module, the TOTP factor's key second", async () => {
		const err = await refusal({ config: configFor("required", TOTP_OFF) });
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({ module: "mfa", kind: "routes" });
		expect(err.cause).toMatchObject({ reason: "mfa-no-counting-factor" });
		const message = (err.cause as Error).message;
		expect(message).toContain("no factor is enabled");
		expect(message).toContain("an installed counting factor through its module's `enabled` key");
		expect(message).toContain(
			"for the TOTP factor, when mfaTotpFactorModule is installed, mfa.factors.totp.enabled (MFA_TOTP_ENABLED)",
		);
		expect(message.indexOf("`enabled` key")).toBeLessThan(message.indexOf("MFA_TOTP_ENABLED"));
	});

	it("refuses required when every enabled factor is one that does not count, naming the enabled kinds — with the TOTP factor's module or without it", async () => {
		for (const withoutTotpModule of [false, true]) {
			const err = await refusal({
				config: configFor("required", TOTP_OFF),
				withoutTotpModule,
				extraModules: [
					contributing(stubFactor("recovery_code", ["recovery"], { counting: false })),
				],
			});
			expect(err.cause, String(withoutTotpModule)).toMatchObject({
				reason: "mfa-no-counting-factor",
			});
			expect((err.cause as Error).message, String(withoutTotpModule)).toContain(
				"the enabled factors (recovery_code) do not count",
			);
		}
	});

	it("accepts required when a counting factor of another package's is the one enabled", async () => {
		await boot({
			config: configFor("required", TOTP_OFF),
			extraModules: [contributing(stubFactor("webauthn", ["hwk", "swk"]))],
		});
	});

	it("refuses an enabled factor whose kind a hint cannot carry — core's hint grammar — naming the kind, under either mode", async () => {
		for (const mode of ["optional", "required"] as const) {
			for (const kind of ["WebAuthn", "web authn", "9totp", "k".repeat(65)]) {
				const err = await refusal({
					config: configFor(mode),
					extraModules: [contributing(stubFactor(kind, ["hwk"]))],
				});
				expect(err.reason, `${mode} ${kind}`).toBe("contribute-factory-failed");
				expect(err.details, `${mode} ${kind}`).toMatchObject({ module: "mfa", kind: "routes" });
				expect(err.cause, kind).toMatchObject({ reason: "mfa-factor-kind-unhintable" });
				const message = (err.cause as Error).message;
				expect(message, kind).toContain(JSON.stringify(kind));
				expect(message, kind).toContain("hints.enrollable");
			}
		}
	});

	/** `count` counting factors of other packages', kinds `extra-1`… */
	const counting = (count: number) =>
		Array.from({ length: count }, (_, i) => contributing(stubFactor(`extra-${i + 1}`, ["hwk"])));

	it("refuses more enabled counting factors than a hint list carries — core's cap, 16 — as mfa-too-many-factors, under either mode", async () => {
		for (const mode of ["optional", "required"] as const) {
			// TOTP and 16 more: 17.
			const err = await refusal({ config: configFor(mode), extraModules: counting(16) });
			expect(err.reason, mode).toBe("contribute-factory-failed");
			expect(err.details, mode).toMatchObject({ module: "mfa", kind: "routes" });
			expect(err.cause, mode).toMatchObject({ reason: "mfa-too-many-factors" });
			const message = (err.cause as Error).message;
			expect(message).toContain("17");
			expect(message).toContain("16");
			expect(message).toContain("hints.enrollable");
		}
	});

	it("boots with 16 enabled counting factors, and counts only those that count", async () => {
		await boot({ extraModules: counting(15) });
		await boot({
			extraModules: [
				...counting(15),
				contributing(stubFactor("recovery_code", ["recovery"], { counting: false })),
			],
		});
	});

	it("holds its cap to core's: a first binding's hint list of 16 kinds is answered, one of 17 refused", async () => {
		const answering = (count: number): SessionRequirement => ({
			name: "mfa",
			secondFactorAuthority: true,
			reach: new Set(["otp", "mfa"]),
			stepUpPage: { url: "/mfa", params: {} },
			remediations: ["mfa.step_up"],
			hintKeys: ["enrollable"],
			admit: async () => ({ outcome: "met" }),
			admitPrimary: async () => ({
				open: async () => ({
					status: 403,
					body: {
						error: "mfa_enrollment_required",
						hints: { enrollable: Array.from({ length: count }, (_, i) => `k${i}`) },
					},
				}),
			}),
		});
		const open = async (count: number) => {
			const admission = await admitPrimary(
				{
					userSessionStore: undefined,
					subjectRevocation: undefined,
					requirements: resolverForTests([answering(count)], { issuer: "https://auth.test" }),
					acrTable: readAcrTable({}),
					logger: undefined,
					auditSink: undefined,
				},
				passwordPrimary({
					subject: "u-alice",
					user: { id: "u-alice" },
					claims: {},
					authTime: new Date(),
					redirectTo: undefined,
					request: {},
				}),
			);
			if (admission.outcome !== "interrupt") throw new Error("not interrupted");
			return admission.open("sess-1");
		};
		await expect(open(16)).resolves.toMatchObject({ status: 403 });
		await expect(open(17)).rejects.toThrow(RangeError);
	});

	it("accepts the kinds a hint carries: lower-case, digits, underscores and hyphens after a letter", async () => {
		await boot({
			extraModules: [
				contributing(stubFactor("web-authn_2", ["hwk"])),
				contributing(stubFactor("recovery_code", ["recovery"], { counting: false })),
			],
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
			[{ maxAttemptsPerTransaction: 11 }, "mfa.maxAttemptsPerTransaction"],
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

	it("refuses an empty endpoints.mfa.url as unset, naming it — before core would refuse the page for its own reason", async () => {
		const config = configFor("required");
		const err = await refusal({
			config: { ...config, endpoints: { ...config.endpoints, mfa: { url: "" } } } as never,
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

describe("the factors' sections are the factors' modules' to read", () => {
	/** An issuer with no host a TOTP issuer could default to: an IPv6 literal would put a colon in the otpauth label. */
	const NO_TOTP_HOST = "https://[2001:db8::1]";
	const withIssuer = (config: ReturnType<typeof configFor>, issuer: string) =>
		({ ...config, oauth: { ...config.oauth, jwt: { ...config.oauth.jwt, issuer } } }) as never;

	it("boots without the TOTP factor's module over another package's counting factor, though no TOTP issuer could be derived: a composition without TOTP is never refused over it", async () => {
		const { handle } = await boot({
			config: withIssuer(configFor("required"), NO_TOTP_HOST),
			withoutTotpModule: true,
			extraModules: [contributing(stubFactor("webauthn", ["hwk", "swk"]))],
		});
		expect(
			[...(handle.components.sessionRequirementResolver?.get("mfa")?.reach ?? [])].sort(),
		).toEqual(["hwk", "mfa", "swk"]);
	});

	it("boots optional without the TOTP factor's module and without any factor, over the same configuration", async () => {
		const { handle } = await boot({
			config: withIssuer(configFor("optional"), NO_TOTP_HOST),
			withoutTotpModule: true,
		});
		expect(handle.components.sessionRequirementResolver?.get("mfa")?.reach.size).toBe(0);
	});

	it("boots without the TOTP factor's module whatever mfa.factors.totp holds, or without it", async () => {
		const totp = mfaSection("required").factors.totp;
		for (const factors of [
			{ totp: { ...totp, digits: 9 } },
			{ totp: { ...totp, issuer: "a:b" } },
			{ totp: { enabled: "yes" } },
			undefined,
		]) {
			const { handle } = await boot({
				config: configFor("required", { factors }),
				withoutTotpModule: true,
				extraModules: [contributing(stubFactor("webauthn", ["hwk", "swk"]))],
			});
			expect(
				[...(handle.components.sessionRequirementResolver?.get("mfa")?.reach ?? [])].sort(),
				JSON.stringify(factors),
			).toEqual(["hwk", "mfa", "swk"]);
		}
	});

	it("boots the TOTP factor over the oauthTokenSettings issuer the composition holds when the configuration's issuer names no host", async () => {
		// The configuration's issuer names no host a TOTP issuer could default
		// to; the slot's does, so the factor's module boots.
		expect(mfaTotpFactorModule.optional).toContain("oauthTokenSettings");
		const { handle } = await boot({
			config: withIssuer(configFor("required"), NO_TOTP_HOST),
			extraModules: [
				defineModule({
					name: "test:oauth-token-settings",
					provides: {
						oauthTokenSettings: () =>
							createTestOAuthTokenSettings({ issuer: "https://login.example.org" }),
					},
				}),
			],
		});
		expect(handle.components.mfaFactorResolver?.get("totp")).toBeDefined();
	});

	it("leaves the refusal to the TOTP factor's module when it is installed: the same issuer refuses the boot there, naming MFA_TOTP_ISSUER", async () => {
		const err = await refusal({ config: withIssuer(configFor("required"), NO_TOTP_HOST) });
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({
			kind: "mfaFactors",
			name: "totp",
			module: "mfa-totp-factor",
		});
		expect((err.cause as Error).message).toContain("MFA_TOTP_ISSUER");
	});
});

describe("the development sample key", () => {
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

	/** The requirement's factory, run as the planner runs it, with the slot as given. */
	const mfaFactory = (deploymentMode: DeploymentMode, deployment: Record<string, unknown>) => {
		const factory = mfaModule({ environment: "development" }).contributes?.sessionRequirements
			?.mfa as unknown as (deps: unknown) => unknown;
		return factory({
			config: { ...sample(), deployment },
			deploymentMode,
			mfaFactorResolver: { get: () => undefined, entries: () => [][Symbol.iterator]() },
			mfaFactorStore: createMemoryMfaFactorStore(),
			mfaTransactionStore: createMemoryMfaTransactionStore(),
			userSessionStore: createInMemoryUserSessionStore(),
			sessionRequirementResolver: resolverForTests([]),
			logger: spyLogger(),
		});
	};

	it('is refused when the deploymentMode slot says "multi", whatever the configuration\'s deployment says', () => {
		expect(() => mfaFactory("multi", { mode: "single" })).toThrow(/deployment\.mode is "multi"/);
	});

	it("refuses a slot it cannot read, absent included, as a TypeError naming it", () => {
		for (const deploymentMode of [undefined, "MULTI"]) {
			expect(() => mfaFactory(deploymentMode as never, {}), String(deploymentMode)).toThrow(
				new TypeError('mfa settings: deploymentMode must be "single", "multi" or "unset"'),
			);
		}
	});

	it("is accepted when the slot says single or unset, whatever the configuration's deployment says", () => {
		for (const deploymentMode of ["single", "unset"] as const) {
			expect(mfaFactory(deploymentMode, { mode: "multi" }), deploymentMode).toBeDefined();
		}
	});

	it.each([
		["refused", "deployment.mode = multi", { mode: "multi" }],
		["accepted with the boot warning", "deployment.mode = single", { mode: "single" }],
		["accepted with the boot warning", "an empty deployment section", {}],
		["accepted with the boot warning", "no deployment section", undefined],
	] as const)(
		"through createApp, the sample key is %s under %s",
		async (outcome, _what, deployment) => {
			const config = {
				...sample(),
				...(deployment === undefined ? {} : { deployment }),
			} as unknown as AppConfig;
			const options = { environment: "development" };
			if (outcome === "refused") {
				// Without the login: under multi the replica-safety guard refuses its
				// in-memory session store first.
				const err = await refusal({ config, options, withoutLogin: true });
				expect(err.reason).toBe("contribute-factory-failed");
				expect((err.cause as Error).message).toContain('deployment.mode is "multi"');
				return;
			}
			const logger = spyLogger();
			await boot({ config, options, logger });
			expect(events(logger, "warn")).toContain("mfa_development_sample_key_in_use");
		},
	);
});

// ---------------------------------------------------------------------------
// A session store that cannot record a step-up
// ---------------------------------------------------------------------------

describe("a session store without recordSecondFactor", () => {
	/** A store of the deployment's own that predates the step-up capability. */
	const withoutStepUp = (): UserSessionStore => {
		const { recordSecondFactor: _recordSecondFactor, ...store } = createInMemoryUserSessionStore();
		return { ...store, kind: "legacy-sessions" };
	};

	it("is said once at boot — mfa_step_up_unsupported, naming the adapter kind — and a password session is sent to log in again where it would step up", async () => {
		const { handle, logger } = await boot({ userSessionStore: withoutStepUp() });
		const said = logger.warn.mock.calls.filter((call) => call[1] === "mfa_step_up_unsupported");
		expect(said).toHaveLength(1);
		expect(said[0]?.[0]).toMatchObject({ store: "userSessionStore", kind: "legacy-sessions" });
		const registered = handle.components.sessionRequirementResolver?.get("mfa");
		const session: UserSession = {
			sid: "sid-1",
			sub: "u-alice",
			authTime: new Date(),
			createdAt: new Date(),
			expiresAt: new Date(Date.now() + 60_000),
			claims: {},
			...passwordSessionAuthentication(),
		};
		expect(
			await registered?.admit({
				session: {
					sid: session.sid,
					sub: session.sub,
					authTime: session.authTime,
					expiresAt: session.expiresAt,
				},
				authentication: requirementSession(session),
				carrier: "cookie",
				subject: session.sub,
				action: ADMISSION_ACTIONS["oauth.authorize"],
				asks: undefined,
				now: new Date(),
			}),
		).toEqual({ outcome: "reauthenticate" });
	});

	it("is not said for a store that records a step-up", async () => {
		const { logger } = await boot();
		expect(events(logger, "warn")).not.toContain("mfa_step_up_unsupported");
	});
});
