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
 * How `oauth`'s consumers of admission are wired (see ADR
 * 2026-09-28-session-admission). Every factory a composition can build by hand
 * takes the branded resolver as a required option (`requirements` on the
 * router, the slot `sessionRequirementResolver` on the grants, whose deps are
 * the module's slots by name) and refuses to build without it; every manifest
 * that hands a consumer its slots lists the synthetic key
 * `sessionRequirementResolver` beside the slots admission reads:
 * `userSessionStore`, `subjectRevocation`, `auditSink`, `logger`. What each
 * consumer answers per outcome is its own suite's.
 */

import {
	type AppConfig,
	AUDIT_SINK_ABSENCE_POLICY,
	type ClientRepository,
	type CodeRepository,
	createMemoryConsentStore,
	createMemoryPendingConsentStore,
	createSymmetricKeyStore,
	type GrantDependencies,
	type SessionRequirementResolver,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
} from "@o3co/auth-provider-core";
import {
	createTestLoginEntry,
	createTestOAuthTokenSettings,
	GrantRegistry,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { describe, expect, it } from "vitest";
import { OAUTH_ROUTER_ADMISSION_ACTIONS } from "#/admissionActions.mjs";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import { createSessionGrant } from "#/grants/session.mjs";
import { oauthAuthorizationGrantsModule } from "#/oauthAuthorization.mjs";
import { oauthSessionGrantModule } from "#/oauthSession.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { grantSettingsFrom } from "./_helpers/grantSettings.mjs";
import { routerInputsOf } from "./_helpers/sections.mjs";

const config = {
	oauth: {
		jwt: { issuer: "https://issuer.example", secret: "test-secret" },
		accessToken: { expiresIn: 300 },
		refreshToken: { expiresIn: 86400 },
	},
	"oauth-session": { enabled: true },
	"oauth-authorization": {
		grants: { authorizationCode: { enabled: true }, refreshToken: { enabled: true } },
	},
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;

const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");

const clientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
};

const codeRepository: CodeRepository = {
	createCode: async () => {
		throw new Error("unused");
	},
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

/** The grant factories' shared slots, without `requirements`. */
const grantDeps = {
	config,
	...grantSettingsFrom(config),
	keyStore,
} as unknown as GrantDependencies & ReturnType<typeof grantSettingsFrom>;

/** The session grant's slots, without `requirements`: it reads the token settings from their slot. */
const sessionGrantDeps = { keyStore, oauthTokenSettings: createTestOAuthTokenSettings() };

describe("the consumers' factories refuse to build without the requirements resolver", () => {
	it("createOAuthRouter throws, naming the option", async () => {
		await expect(
			createOAuthRouter(express, {
				loginEntry: createTestLoginEntry(),
				registry: new GrantRegistry(),
				...routerInputsOf(config),
				clientRepository,
				codeRepository,
				keyStore,
				// @ts-expect-error — the option is required; the refusal at runtime is the test.
				requirements: undefined,
			}),
		).rejects.toThrow(/requirements/);
	});

	it("createOAuthRouter builds with resolverForTests", async () => {
		const { router } = await createOAuthRouter(express, {
			loginEntry: createTestLoginEntry(),
			registry: new GrantRegistry(),
			...routerInputsOf(config),
			clientRepository,
			codeRepository,
			keyStore,
			requirements: resolverForTests([]),
		});
		expect(router).toBeDefined();
	});

	it("createOAuthRouter refuses, where it is built, a resolver on which /authorize's or the consent step's action is not registered, naming the handler and the action", async () => {
		const registry = new GrantRegistry();
		registry.register("authorization_code", {
			handle: async () => {
				throw new Error("unused");
			},
		} as never);
		const build = (actions: Readonly<Record<string, { readonly grade: "use" }>>) =>
			createOAuthRouter(express, {
				loginEntry: createTestLoginEntry(),
				registry,
				...routerInputsOf(config),
				clientRepository,
				codeRepository,
				keyStore,
				consentStore: createMemoryConsentStore(),
				pendingConsentStore: createMemoryPendingConsentStore(),
				requirements: resolverForTests([], { actions }),
			});
		await expect(build({})).rejects.toThrow(
			/^createAuthorizeHandler: admits "oauth\.authorize", which no module registers/,
		);
		await expect(build({ "oauth.authorize": { grade: "use" } })).rejects.toThrow(
			/^createConsentRouter: admits "oauth\.consent", which no module registers/,
		);
		await expect(build(OAUTH_ROUTER_ADMISSION_ACTIONS)).resolves.toBeDefined();
	});

	it("createSessionGrant throws, naming the option", () => {
		// @ts-expect-error — the option is required; the refusal at runtime is the test.
		expect(() => createSessionGrant(sessionGrantDeps)).toThrow(/requirements/);
		expect(() =>
			createSessionGrant({ ...sessionGrantDeps, sessionRequirementResolver: resolverForTests([]) }),
		).not.toThrow();
	});

	it("createAuthorizationGrant throws, naming the option", () => {
		const deps = { ...grantDeps, clientRepository, codeRepository };
		// @ts-expect-error — the option is required; the refusal at runtime is the test.
		expect(() => createAuthorizationGrant(deps)).toThrow(/requirements/);
		expect(() =>
			createAuthorizationGrant({ ...deps, sessionRequirementResolver: resolverForTests([]) }),
		).not.toThrow();
	});

	it("createRefreshTokenGrant throws, naming the option", () => {
		// @ts-expect-error — the option is required; the refusal at runtime is the test.
		expect(() => createRefreshTokenGrant(grantDeps)).toThrow(/requirements/);
		expect(() =>
			createRefreshTokenGrant({ ...grantDeps, sessionRequirementResolver: resolverForTests([]) }),
		).not.toThrow();
	});

	it("each refuses a resolver the planner did not build at construction, naming the factory — core's checkResolver, the one check every consumer factory runs", async () => {
		const forged = {
			get: () => undefined,
			entries: () => [][Symbol.iterator](),
		} as unknown as SessionRequirementResolver;
		const refusal = (factory: string) =>
			new RegExp(
				`^${factory}: requirements must be the sessionRequirementResolver the boot planner built`,
			);
		await expect(
			createOAuthRouter(express, {
				loginEntry: createTestLoginEntry(),
				registry: new GrantRegistry(),
				...routerInputsOf(config),
				clientRepository,
				codeRepository,
				keyStore,
				requirements: forged,
			}),
		).rejects.toThrow(refusal("createOAuthRouter"));
		expect(() =>
			createSessionGrant({ ...sessionGrantDeps, sessionRequirementResolver: forged }),
		).toThrow(refusal("createSessionGrant"));
		expect(() =>
			createAuthorizationGrant({
				...grantDeps,
				clientRepository,
				codeRepository,
				sessionRequirementResolver: forged,
			}),
		).toThrow(refusal("createAuthorizationGrant"));
		expect(() =>
			createRefreshTokenGrant({ ...grantDeps, sessionRequirementResolver: forged }),
		).toThrow(refusal("createRefreshTokenGrant"));
	});
});

describe("the grant manifests declare what admission reads", () => {
	it("oauthSessionGrantModule requires sessionRequirementResolver and lists the slots admission reads", () => {
		const module = oauthSessionGrantModule;
		expect(module.requires).toContain("sessionRequirementResolver");
		expect(module.optional).toContain("userSessionStore");
		expect(module.optional).toContain("sessionLifecycleStore");
		expect(module.optional).toContain("subjectRevocation");
		expect(module.optional).toContain("auditSink");
		expect(module.optional).toContain("logger");
		// Optional to wire, not optional to decide: the two slots with a
		// declared absence carry the same policies every other consumer attaches.
		expect(module.absencePolicies?.subjectRevocation).toBe(SUBJECT_REVOCATION_ABSENCE_POLICY);
		expect(module.absencePolicies?.auditSink).toBe(AUDIT_SINK_ABSENCE_POLICY);
	});

	it("oauthSessionGrantModule is off, registering nothing it declares, when its section says so", () => {
		expect(oauthSessionGrantModule.section?.isEnabled?.({ enabled: false })).toBe(false);
		expect(oauthSessionGrantModule.section?.isEnabled?.(undefined)).toBe(false);
	});

	it("oauthAuthorizationGrantsModule requires sessionRequirementResolver and lists the slots admission reads", () => {
		const module = oauthAuthorizationGrantsModule;
		expect(module.requires).toContain("sessionRequirementResolver");
		expect(module.optional).toContain("userSessionStore");
		expect(module.optional).toContain("sessionLifecycleStore");
		expect(module.optional).toContain("subjectRevocation");
		expect(module.optional).toContain("auditSink");
		expect(module.optional).toContain("logger");
		expect(module.absencePolicies?.subjectRevocation).toBe(SUBJECT_REVOCATION_ABSENCE_POLICY);
		expect(module.absencePolicies?.auditSink).toBe(AUDIT_SINK_ABSENCE_POLICY);
	});
});
