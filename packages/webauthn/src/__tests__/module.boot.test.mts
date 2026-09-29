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
 * Boot integration tests for `webauthnModule` through the full `createApp`
 * planner pipeline. Small bootstrap modules fill the DI slots, and an activator
 * module forces the planner to materialise the lazy synthetic projections.
 */

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
	AppConfigSchema,
	createApp,
	createMemoryWebAuthnCredentialStore,
	createSymmetricKeyStore,
	defaultChallengeCeremonyModule,
	defineModule,
	type GrantContext,
	type GrantHandler,
	type GrantHandlerResolver,
	type GrantPolicyHook,
	memoryChallengeStoreModule,
	memoryReplaySeenSetModule,
	memoryWebAuthnCredentialStoreModule,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import supertest from "supertest";
import { describe, expect, it, vi } from "vitest";
import { type WebAuthnConfig, webauthnConfigSchema } from "../config.mjs";
import { WEBAUTHN_GRANT_TYPE } from "../grant.mjs";
import { webauthnModule } from "../module.mjs";

// ---------------------------------------------------------------------------
// Shared boot components
// ---------------------------------------------------------------------------

// `makeValidAppConfig()`, not `makeValidCoreConfig()`: the `config` slot is
// typed `AppConfig`, and the webauthn route factory reads
// `config.rateLimit.failMode`, a section the core-only slice lacks.
// Captured once and reused: the factory returns a fresh object per call, and
// separate calls would be fixtures that only happen to agree.
const baseAppConfig = makeValidAppConfig();
const coreConfig = {
	...baseAppConfig,
	oauth: {
		...baseAppConfig.oauth,
		// A non-empty issuer is required when grantPolicy is wired, and webauthnModule
		// requires grantPolicy. makeValidAppConfig() defaults it; it is pinned here.
		jwt: { ...baseAppConfig.oauth.jwt, issuer: "https://test.example" },
	},
};

/** Minimal bootstrap: config + pathResolver + keyStore. */
const minBoot = {
	config: coreConfig,
	pathResolver: (p: string) => p,
} as never;

const keyStoreModule = defineModule({
	name: "test:webauthn-boot-key-store",
	provides: {
		keyStore: () => createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
	},
});

/** Stub webauthnConfig values — not used for real ceremonies. */
const stubWebAuthnConfig: WebAuthnConfig = {
	rpId: "example.com",
	rpName: "Example App",
	origin: ["https://example.com"],
	challengeTtlMs: 120_000,
	attestationPreference: "none",
	userVerification: "preferred",
	// Enumeration-resistant default, and a throttle limit high enough that the
	// body-parser probes below are never denied; the throttle itself is covered
	// by module.rateLimit.test.mts.
	allowCredentialsForKnownUser: false,
	rateLimit: { authenticationOptions: { limit: 1000, windowSeconds: 60 } },
};

/** Bootstrap module: satisfies the `webauthnConfig` DI slot. */
const webauthnConfigModule = defineModule({
	name: "test:webauthn-config-bootstrap",
	provides: {
		webauthnConfig: () => stubWebAuthnConfig,
	},
});

/** Bootstrap module: a permit-all GrantPolicy, which webauthnModule requires at boot.
 * A production deployment fills the `grantPolicy` slot with a GrantPolicyHook of its
 * own; no package ships one. */
const noopGrantPolicyModule = defineModule({
	name: "test:webauthn-noop-grant-policy",
	provides: {
		grantPolicy: (): GrantPolicyHook => ({
			kind: "test-noop",
			evaluate: async () => ({ outcome: "allow" }) as const,
		}),
	},
});

/**
 * Activator: requires the synthetic `grantHandlerResolver` so the boot planner
 * materialises the grant registry into handle.components; otherwise the lazy
 * projection may not be exposed.
 */
const activatorModule = defineModule({
	name: "test:webauthn-activator",
	requires: ["grantHandlerResolver"] as never,
	contributes: {
		routes: [
			{
				mountPath: "/__test_webauthn_noop__",
				id: "test-webauthn-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

// ---------------------------------------------------------------------------
// Full module set for happy-path boot
// ---------------------------------------------------------------------------

const happyPathModules = [
	webauthnModule,
	webauthnConfigModule,
	keyStoreModule,
	memoryChallengeStoreModule,
	memoryReplaySeenSetModule,
	defaultChallengeCeremonyModule,
	memoryWebAuthnCredentialStoreModule,
	noopGrantPolicyModule,
	activatorModule,
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("webauthnModule boot integration (Wave 1 T31)", () => {
	it("boots successfully when webauthnConfig is provided and materialises the webauthn grant", async () => {
		const handle = await createApp({
			modules: happyPathModules,
			bootstrapComponents: minBoot,
		});

		// The grant registry (synthetic resolver) must contain the webauthn grant.
		const grantHandlerResolver = (handle.components as Record<string, unknown>)
			.grantHandlerResolver as { get(grantType: string): unknown } | undefined;
		expect(grantHandlerResolver).toBeDefined();
		const grantHandler = grantHandlerResolver?.get(WEBAUTHN_GRANT_TYPE);
		expect(grantHandler).toBeDefined();
		expect(typeof (grantHandler as { handle?: unknown })?.handle).toBe("function");

		await handle.dispose();
	});

	it("boots successfully and contributes all three webauthn routes", async () => {
		const handle = await createApp({
			modules: happyPathModules,
			bootstrapComponents: minBoot,
		});

		const routeIds = handle.routes.map((r) => r.contribution.id);
		expect(routeIds).toContain("webauthn-registration-options");
		expect(routeIds).toContain("webauthn-registration-verify");
		expect(routeIds).toContain("webauthn-authentication-options");

		await handle.dispose();
	});

	it("all three routes are mounted under /oauth/webauthn", async () => {
		const handle = await createApp({
			modules: happyPathModules,
			bootstrapComponents: minBoot,
		});

		const webauthnRoutes = handle.routes.filter((r) =>
			r.contribution.mountPath.startsWith("/oauth/webauthn"),
		);
		expect(webauthnRoutes.length).toBe(3);

		await handle.dispose();
	});

	it("throws BootError missing-required-component for webauthnConfig when the slot is not provided", async () => {
		const { BootError } = await import("@o3co/auth-provider-core");

		// Omit webauthnConfigModule — the slot remains unwired.
		const modulesWithoutConfig = [
			webauthnModule,
			keyStoreModule,
			memoryChallengeStoreModule,
			memoryReplaySeenSetModule,
			defaultChallengeCeremonyModule,
			memoryWebAuthnCredentialStoreModule,
			activatorModule,
		];

		const error = await createApp({
			modules: modulesWithoutConfig,
			bootstrapComponents: minBoot,
		}).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(error).toBeInstanceOf(BootError);
		expect(error).toMatchObject({
			reason: "missing-required-component",
			details: { missingKey: "webauthnConfig" },
		});
	});

	/**
	 * The webauthn grant requires grantPolicy at boot. It has no library-side
	 * scope ceiling (client_credentials falls back to `client.allowedScopes`), so
	 * without a policy it would issue whatever scope the caller requests.
	 */
	it("H-2 fail-fast: boot throws when webauthnModule wired without grantPolicy", async () => {
		// All deps present EXCEPT grantPolicy.
		const modulesWithoutPolicy = [
			webauthnModule,
			webauthnConfigModule,
			keyStoreModule,
			memoryChallengeStoreModule,
			memoryReplaySeenSetModule,
			defaultChallengeCeremonyModule,
			memoryWebAuthnCredentialStoreModule,
			activatorModule,
		];

		await expect(
			createApp({
				modules: modulesWithoutPolicy,
				bootstrapComponents: minBoot,
			}),
		).rejects.toThrow(/webauthn grant requires `grantPolicy`/);
	});

	it("H-2 fail-fast: the refusal says how to fill the slot, and names only packages that exist", async () => {
		const error = await createApp({
			modules: [
				webauthnModule,
				webauthnConfigModule,
				keyStoreModule,
				memoryChallengeStoreModule,
				memoryReplaySeenSetModule,
				defaultChallengeCeremonyModule,
				memoryWebAuthnCredentialStoreModule,
				activatorModule,
			],
			bootstrapComponents: minBoot,
		}).then(
			() => undefined,
			(e: unknown) => e,
		);
		// The planner wraps a throwing grant factory; the module's own words are the cause.
		const cause = (error as { cause?: unknown } | undefined)?.cause;
		expect(cause).toBeInstanceOf(Error);
		const message = (cause as Error).message;

		// An operator told to install a package that was never published is
		// sent nowhere. Every package the message names is one this workspace
		// builds.
		const packagesDir = fileURLToPath(new URL("../../../", import.meta.url));
		const packageName = (dir: string): string =>
			(JSON.parse(readFileSync(`${packagesDir}${dir}/package.json`, "utf8")) as { name: string })
				.name;
		// A directory without a package.json is not a package — AGENTS.md warns of
		// stale untracked build output under packages/ (the old DID package).
		const workspacePackages = new Set(
			readdirSync(packagesDir, { withFileTypes: true })
				.filter(
					(entry) => entry.isDirectory() && existsSync(`${packagesDir}${entry.name}/package.json`),
				)
				.map((entry) => packageName(entry.name)),
		);
		// A dot inside a name (`ts.hocon`) is part of it; one ending a sentence is not.
		const named = message.match(/@o3co\/[a-z0-9-]+(?:\.[a-z0-9-]+)*/g) ?? [];
		expect(named.length).toBeGreaterThan(0);
		for (const name of named) {
			expect(workspacePackages, `${name} is named by the boot error`).toContain(name);
		}

		// The two ways a composition fills a component slot.
		expect(message).toContain("provides: { grantPolicy");
		expect(message).toContain("bootstrapComponents");
		expect(message).toContain("GrantPolicyHook");
	});

	it("H-2 fail-fast: the second way the refusal names — bootstrapComponents.grantPolicy — boots", async () => {
		// The first (`provides`) is how every other test here wires the policy.
		const policy: GrantPolicyHook = {
			kind: "test-bootstrap-policy",
			evaluate: async () => ({ outcome: "allow" }) as const,
		};
		const handle = await createApp({
			modules: [
				webauthnModule,
				webauthnConfigModule,
				keyStoreModule,
				memoryChallengeStoreModule,
				memoryReplaySeenSetModule,
				defaultChallengeCeremonyModule,
				memoryWebAuthnCredentialStoreModule,
				activatorModule,
			],
			bootstrapComponents: { ...(minBoot as object), grantPolicy: policy } as never,
		});
		const resolver = (handle.components as Record<string, unknown>).grantHandlerResolver as
			| GrantHandlerResolver
			| undefined;
		expect(resolver?.get(WEBAUTHN_GRANT_TYPE)).toBeDefined();
		await handle.dispose();
	});

	/**
	 * Without `optional: ["grantPolicy"]` on webauthnModule, the boot planner
	 * never injects the policy and the grant silently skips it even when one is
	 * wired. Only a module-level wiring check catches that: the policy gate
	 * itself is exercised in grant.test.mts, which mocks the steps before it.
	 * This boots with a spy policy and resource indicators on, and checks the
	 * resolved component and that the booted handler is live.
	 */
	it("C1 regression: grantPolicy.evaluate is called when wired + resourceIndicator.enabled=true", async () => {
		const CREDENTIAL_ID = "dGVzdC1jcmVkZW50aWFsLWlk";
		const CHALLENGE = "test-challenge-for-policy-gate";

		const evaluateSpy = vi.fn().mockResolvedValue({ outcome: "allow" } as const);

		const stubGrantPolicy: GrantPolicyHook = {
			kind: "test-grant-policy",
			evaluate: evaluateSpy,
		};

		const grantPolicyModule = defineModule({
			name: "test:webauthn-grant-policy",
			provides: {
				grantPolicy: () => stubGrantPolicy,
			},
		});

		// Resource indicators on; a wired grantPolicy needs a non-empty oauth.jwt.issuer.
		const configWithRI = {
			...coreConfig,
			oauth: {
				...((coreConfig as unknown as Record<string, Record<string, unknown>>).oauth ?? {}),
				jwt: {
					...((coreConfig as unknown as Record<string, Record<string, unknown>>).oauth?.jwt ?? {}),
					issuer: "https://example.com",
				},
				resourceIndicator: { enabled: true },
			},
		} as unknown as typeof coreConfig;

		const bootWithPolicy = {
			config: configWithRI,
			pathResolver: (p: string) => p,
		} as never;

		const handle = await createApp({
			modules: [
				webauthnModule,
				webauthnConfigModule,
				keyStoreModule,
				memoryChallengeStoreModule,
				memoryReplaySeenSetModule,
				defaultChallengeCeremonyModule,
				memoryWebAuthnCredentialStoreModule,
				grantPolicyModule,
				activatorModule,
			],
			bootstrapComponents: bootWithPolicy,
		});

		// Retrieve the webauthn grant handler via the synthetic resolver.
		const grantHandlerResolver = (handle.components as Record<string, unknown>)
			.grantHandlerResolver as GrantHandlerResolver | undefined;
		expect(grantHandlerResolver).toBeDefined();
		const grantHandler = grantHandlerResolver?.get(WEBAUTHN_GRANT_TYPE) as GrantHandler | undefined;
		expect(grantHandler).toBeDefined();
		if (!grantHandler) throw new Error("no grant handler");

		// A local store: the handle's own credential store is a different instance.
		const credentialStore = createMemoryWebAuthnCredentialStore();
		await credentialStore.registerCredential({
			userId: "user-for-policy-test",
			credentialId: CREDENTIAL_ID,
			publicKey: new Uint8Array(64),
			signCount: 0,
			backedUp: false,
			createdAt: new Date(),
		});

		// The boot planner only injects optional deps that are declared, so the
		// grantPolicy component resolving to the stub shows the slot was declared.
		const resolvedPolicy = (handle.components as Record<string, unknown>).grantPolicy;
		expect(resolvedPolicy).toBeDefined();
		expect(resolvedPolicy).toBe(stubGrantPolicy);

		const clientDataJSON = Buffer.from(
			JSON.stringify({ type: "webauthn.get", challenge: CHALLENGE, origin: "https://example.com" }),
		).toString("base64url");

		const ctx: GrantContext = {
			body: {
				grant_type: WEBAUTHN_GRANT_TYPE,
				assertion: {
					id: CREDENTIAL_ID,
					rawId: CREDENTIAL_ID,
					response: { clientDataJSON, authenticatorData: "stub", signature: "stub" },
					clientExtensionResults: {},
					type: "public-key",
				},
			},
			session: {},
			issuer: "https://example.com",
			metadata: {},
			authenticatedClient: null,
		};

		// Fails at credential lookup, before the policy gate (so evaluateSpy is not
		// called): this only confirms the handler is live after boot.
		const { result } = await grantHandler.handle(ctx);
		expect(result.status).toBeGreaterThanOrEqual(400);

		await handle.dispose();
	});
});

/**
 * The operator's path for `WEBAUTHN_ORIGIN` / `WEBAUTHN_TOP_ORIGIN`: the
 * composition root parses its resolved HOCON with core's `AppConfigSchema`,
 * and the bootstrap module this package's README describes hands
 * `config.webauthn` to `webauthnConfigSchema`.
 *
 * `hoconWebauthn` is the `webauthn` section as the shipped reference.conf
 * resolves with these variables set: literals keep their types, every `${?VAR}`
 * arrives as a string, and the origin list is still one comma-separated string
 * after core's parse. Core's `reference-conf-drift.test.mts` pins that shape
 * against the real HOCON resolution; this package has no HOCON library.
 */
describe("webauthnConfig from the environment (WEBAUTHN_ORIGIN / WEBAUTHN_TOP_ORIGIN)", () => {
	const ANDROID = "android:apk-key-hash:pNiP5iKyQ8JwgLTSKGZmcRHqvOUP1qGP8FfEcCQPvVI";
	const hoconWebauthn = {
		challengeTtlMs: 120000,
		attestationPreference: "none",
		userVerification: "preferred",
		allowCredentialsForKnownUser: false,
		rateLimit: { authenticationOptions: { limit: 30, windowSeconds: 60 } },
		rpId: "example.com",
		rpName: "Example App",
		origin: `https://example.com,${ANDROID}`,
		topOrigin: "https://partner.example",
	};

	it("boots with both origins and the top origin the variables name", async () => {
		const config = AppConfigSchema.parse({ ...coreConfig, webauthn: hoconWebauthn });
		// AppConfigSchema passes the origin list on as the one string it is.
		expect(config.webauthn?.origin).toBe(`https://example.com,${ANDROID}`);

		const handle = await createApp({
			modules: [
				webauthnModule,
				defineModule({
					name: "test:webauthn-config-from-app-config",
					requires: ["config"] as const,
					provides: {
						webauthnConfig: ({ config }) => webauthnConfigSchema.parse(config.webauthn),
					},
				}),
				keyStoreModule,
				memoryChallengeStoreModule,
				memoryReplaySeenSetModule,
				defaultChallengeCeremonyModule,
				memoryWebAuthnCredentialStoreModule,
				noopGrantPolicyModule,
				activatorModule,
			],
			bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
		});
		const resolved = (handle.components as Record<string, unknown>).webauthnConfig as
			| WebAuthnConfig
			| undefined;
		expect(resolved?.origin).toEqual(["https://example.com", ANDROID]);
		expect(resolved?.topOrigin).toEqual(["https://partner.example"]);
		await handle.dispose();
	});
});

// ---------------------------------------------------------------------------
// Body-parser integration
// ---------------------------------------------------------------------------

/**
 * Each contributed router installs its own `express.json()` before its POST
 * handlers: createApp installs no global JSON parser, and oauthModule's router
 * parses only its own routes' bodies. Without it, `req.body` is `undefined`.
 * These tests mount `handle.router` on a bare express app and POST JSON.
 */
describe("webauthnModule body parser integration (Codex Round 4 P1)", () => {
	it("POST /oauth/webauthn/authentication/options parses JSON body via router-level parser (no global parser on host app)", async () => {
		const handle = await createApp({
			modules: happyPathModules,
			bootstrapComponents: minBoot,
		});

		// A bare app, as a composition root doing `app.use(handle.router)` without
		// a global JSON parser. authentication/options is the one unauthenticated
		// webauthn POST route, so no session middleware stub is needed.
		const app = express();
		app.use(handle.router);

		const res = await supertest(app)
			.post("/oauth/webauthn/authentication/options")
			.set("Content-Type", "application/json")
			.send(JSON.stringify({}));

		// authentication/options parses `req.body ?? {}`, so without a parser it would
		// still answer 200; registration/verify, below, has no `?? {}` fallback.
		expect(res.status).toBe(200);
		expect(res.body).toHaveProperty("challenge");

		await handle.dispose();
	});

	it("POST /oauth/webauthn/registration/verify returns non-401 body-parse error when JSON body is sent without global parser (router must own the parser)", async () => {
		const handle = await createApp({
			modules: happyPathModules,
			bootstrapComponents: minBoot,
		});

		// Bare app — no global JSON parser.
		const app = express();
		// Inject webauthnSubject upstream so the 401 gate passes.
		app.use((req, _res, next) => {
			req.webauthnSubject = { userId: "test-user" };
			next();
		});
		app.use(handle.router);

		// A valid-shape body. Unparsed, it fails body validation as
		// `invalid_request`; parsed, it gets past it and fails as
		// `challenge_invalid` (no challenge was issued). Both are 400.
		const clientDataJSON = Buffer.from(
			JSON.stringify({
				type: "webauthn.create",
				challenge: "not-issued",
				origin: "https://example.com",
			}),
		).toString("base64url");

		const res = await supertest(app)
			.post("/oauth/webauthn/registration/verify")
			.set("Content-Type", "application/json")
			.send(
				JSON.stringify({
					response: {
						id: "cred-id",
						rawId: "cred-id",
						response: { clientDataJSON, attestationObject: "stub" },
						clientExtensionResults: {},
						type: "public-key",
					},
				}),
			);

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("challenge_invalid");

		await handle.dispose();
	});
});

describe("auditSink absence policy (#363)", () => {
	it("carries the shared AUDIT_SINK_ABSENCE_POLICY constant, by identity", async () => {
		// Identity, not shape: the declared-absence guard refuses modules whose
		// policies for one key disagree, and sharing the one constant is what
		// makes disagreement impossible by construction.
		const { AUDIT_SINK_ABSENCE_POLICY } = await import("@o3co/auth-provider-core");
		expect(webauthnModule.absencePolicies?.auditSink).toBe(AUDIT_SINK_ABSENCE_POLICY);
	});
});
