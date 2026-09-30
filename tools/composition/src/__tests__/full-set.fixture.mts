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
 * The full set: the standalone template's composition (its fixture,
 * `all-modules-composition.fixture.mts`, imported whole) with every workspace
 * package the template does not depend on added the way a deployment adds
 * them to that manifest — the device grant, DPoP, mTLS, token exchange,
 * WebAuthn, the MFA package (`mfaModules` over the MFA stores, `mfa.mode =
 * "optional"`, a key of the deployment's own), and the Apple and GitHub
 * federations. What the template's fixture substitutes, this one inherits.
 * What it adds:
 *
 * - The settings with no default laid over the configuration. The added
 *   packages' `reference.conf` files are layered because their modules
 *   declare them (`section.reference`), as `app.mts` does.
 * - The small modules each package's README has a deployment write: the
 *   WebAuthn, Apple and GitHub config bridges and a `grantPolicy` (WebAuthn
 *   refuses to boot without one, and no package ships one). The federation
 *   bridges point each adapter's `fetch` at a fake upstream.
 * - mTLS in-process on its `header` source from a loopback peer — the shape
 *   a TLS-terminating proxy gives it — with the mTLS package's test
 *   certificate.
 * - WebAuthn registration reads `req.webauthnSubject`, which the package's
 *   `webauthnSessionSubjectModule` sets from the admitted browser session;
 *   the deployment's mapper here is the session's opaque subject.
 *
 * The fakes are shared by every boot in a file and put back as they were made
 * before each one (`resettable`, from the template's fixture).
 */

import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import {
	type AdmissionDeps,
	type AppConfig,
	consoleLogger,
	createMemoryWebAuthnCredentialStore,
	defaultChallengeCeremonyModule,
	defineModule,
	type GrantPolicyHook,
	type InterruptionAnswer,
	loggableError,
	type Module,
	memoryChallengeStoreModule,
	memoryDeviceCodeStoreModule,
	memoryMfaFactorStoreModule,
	memoryMfaTransactionStoreModule,
	memoryWebAuthnCredentialStoreModule,
	type PrimaryAuthentication,
	type PrimaryContinuation,
	type RequirementInterruption,
	resumePrimary,
	type SessionRequirement,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
} from "@o3co/auth-provider-core";
import { createFakeIdp, type FakeIdp } from "@o3co/auth-provider-core/testing";
import { DEVICE_CODE_GRANT_TYPE, deviceGrantModule } from "@o3co/auth-provider-device-grant";
import { dpopModule } from "@o3co/auth-provider-dpop";
import { appleFederationModule } from "@o3co/auth-provider-federation-apple";
import { githubFederationModule } from "@o3co/auth-provider-federation-github";
import { mfaModules } from "@o3co/auth-provider-mfa";
import { mtlsModule } from "@o3co/auth-provider-mtls";
import {
	TOKEN_EXCHANGE_GRANT_TYPE,
	tokenExchangeModule,
} from "@o3co/auth-provider-oauth-token-exchange";
import {
	redisChallengeStoreModule,
	redisDeviceCodeStoreModule,
	redisMfaFactorStoreModule,
	redisMfaTransactionStoreModule,
} from "@o3co/auth-provider-redis";
import { answerInterruption, establishSession } from "@o3co/auth-provider-session";
import {
	type ComposeOptions,
	type Composition,
	compose,
	ISSUER,
	resettable,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import {
	webauthnConfigSchema,
	webauthnModule,
	webauthnSessionSubjectModule,
} from "@o3co/auth-provider-webauthn";
import type { RequestHandler } from "express";
import {
	createFakeGithub,
	type FakeGithub,
} from "../../../../packages/federation-github/src/__tests__/fake-github.mts";

/** The mTLS package's self-signed client certificate. */
export const CLIENT_CERTIFICATE = readFileSync(
	new URL("../../../../packages/mtls/src/__tests__/fixtures/leaf.pem", import.meta.url),
	"utf8",
);

export const APPLE_LANDING = "https://app.test/apple";
export const GITHUB_LANDING = "https://app.test/github";

// ---------------------------------------------------------------------------
// Switches
// ---------------------------------------------------------------------------

/**
 * What the full set turns on beyond the template's own switches. Each is the
 * switch a deployment flips: a config key where the package has one, the
 * module's presence where it does not (token exchange, WebAuthn).
 */
export interface Features {
	readonly deviceGrant: boolean;
	readonly dpop: boolean;
	readonly mtls: boolean;
	readonly tokenExchange: boolean;
	readonly webauthn: boolean;
	readonly apple: boolean;
	readonly github: boolean;
	/**
	 * The MFA package: installed is on (ADR 2026-09-28-session-admission), so
	 * its switch is its modules' presence — with `mfa.mode = "optional"` and
	 * `mfa` declared — or their absence with `mfa.mode = "off"`.
	 */
	readonly mfa: boolean;
}

export const ALL_ON: Features = {
	deviceGrant: true,
	dpop: true,
	mtls: true,
	tokenExchange: true,
	webauthn: true,
	apple: true,
	github: true,
	mfa: true,
};

/**
 * The deployment's own MFA key (canonical base64 of 32 bytes), one per test
 * file, so every replica a file boots shares it — never the development
 * sample key: the full set boots as `production` does.
 */
export const MFA_KEY = randomBytes(32).toString("base64");

/** Which store backs each added feature: memory on one replica, Redis on several. */
export type Stores = "memory" | "redis";

/** The settings with no default, laid over the resolved config for `features`. */
function withFeatures(config: AppConfig, features: Features): AppConfig {
	const c = config as unknown as {
		mfa?: Record<string, unknown>;
		"device-grant"?: Record<string, unknown>;
		dpop?: Record<string, unknown>;
		mtls?: Record<string, unknown>;
		federations: Record<string, Record<string, unknown>>;
		webauthn?: Record<string, unknown>;
		core?: { sessionRequirements?: { expected?: readonly string[] } };
	};
	return {
		...config,
		// A deployment that installs MFA declares it — as the template does
		// from a mode other than `off` — and one that adds requirements of its
		// own declares them beside it, over the template's `[]`. Applied to
		// phase one's switches and again to the configuration as resolved, so
		// each name is kept once.
		core: {
			...c.core,
			sessionRequirements: {
				expected: [
					...new Set([
						...(c.core?.sessionRequirements?.expected ?? []),
						...(features.mfa ? ["mfa"] : []),
						...FIXTURE_REQUIREMENTS,
					]),
				],
			},
		},
		// The MFA package on, as a deployment turns it on: `optional` — users
		// with a factor are challenged, nobody is forced — and a key of its own.
		mfa: features.mfa
			? { ...c.mfa, mode: "optional", encryptionKeys: [{ key: MFA_KEY }] }
			: { ...c.mfa, mode: "off" },
		"device-grant": {
			...c["device-grant"],
			enabled: features.deviceGrant,
			verificationUri: `${ISSUER}/device`,
		},
		dpop: { ...c.dpop, enabled: features.dpop },
		// The forwarded certificate in the header the package's reference names,
		// `x-forwarded-client-cert`.
		mtls: {
			...c.mtls,
			enabled: features.mtls,
			source: "header",
			certHeaderDialect: "plain-pem",
			// supertest dials loopback, which the app sees as the forwarding hop.
			trustedProxies: ["loopback"],
			mode: "self-signed",
		},
		webauthn: {
			...c.webauthn,
			rpId: "auth.test",
			rpName: "Composition",
			origin: [ISSUER],
		},
		federations: {
			...c.federations,
			apple: {
				enabled: features.apple,
				type: "apple",
				clientId: "com.example.composition",
				clientSecret: "apple-static-client-secret",
				callbackURL: `${ISSUER}/session/oauth/federation/apple/callback`,
				clientUrl: APPLE_LANDING,
			},
			github: {
				enabled: features.github,
				type: "github",
				clientId: "github-client",
				clientSecret: "github-secret",
				callbackURL: `${ISSUER}/session/oauth/federation/github/callback`,
				clientUrl: GITHUB_LANDING,
			},
		},
	} as unknown as AppConfig;
}

// ---------------------------------------------------------------------------
// The modules a deployment writes
// ---------------------------------------------------------------------------

/** The README's WebAuthn bootstrap: the `webauthn` section, through the package's schema. */
const webauthnConfigModule = defineModule({
	name: "deployment:webauthn-config",
	requires: ["config"] as const,
	provides: {
		webauthnConfig: ({ config }) =>
			webauthnConfigSchema.parse((config as unknown as { webauthn: unknown }).webauthn),
	},
});

/**
 * The deployment's grant policy. WebAuthn's grant refuses to boot without one
 * and no package ships one; this one allows what each grant allows by itself,
 * so every flow below is the grant's own answer.
 */
const grantPolicyModule = defineModule({
	name: "deployment:grant-policy",
	provides: {
		grantPolicy: (): GrantPolicyHook => ({
			kind: "deployment-allow",
			evaluate: async () => ({ outcome: "allow" }) as const,
		}),
	},
});

/**
 * The WebAuthn README's session bridge: the package's module, which admits the
 * browser's session as `webauthn.register`, with the deployment's mapper — the
 * template's subjects are opaque (`u-alice`), so the subject is the handle.
 */
const webauthnSubjectModule = webauthnSessionSubjectModule({
	subjectFor: (session) => ({ userId: session.sub }),
});

/** The fixture's two session requirements, in registration order (see `requirementModules`). */
export const FIXTURE_REQUIREMENTS = ["fixture-page", "fixture-bare"] as const;

/**
 * The 403 the fixture requirements answer a login they interrupt with: the
 * closed body core validates, a hint under the one key the page requirement
 * declares.
 */
export const FIXTURE_INTERRUPTION = {
	page: { status: 403, body: { error: "fixture_page_required", hints: { fixture_hint: true } } },
	bare: { status: 403, body: { error: "fixture_bare_required" } },
} as const;

/** A ceremony a fixture requirement opened, as the full set records it for a test. */
export interface FixtureCeremony {
	readonly requirement: (typeof FIXTURE_REQUIREMENTS)[number];
	/** The express session the ceremony is bound to: the one the interrupted route regenerated. */
	readonly sessionId: string;
	/** What core handed the requirement to persist, and what its completion presents to `resumePrimary`. */
	readonly continuation: PrimaryContinuation;
}

/** Where each fixture requirement's completion route is mounted: `POST <path>/complete`. */
export const FIXTURE_COMPLETION = {
	page: "/fixture/page",
	bare: "/fixture/bare",
} as const;

const FIXTURE_UNAVAILABLE = {
	error: "temporarily_unavailable",
	error_description: "Session store unavailable",
};

/**
 * Two session requirements a deployment might write, registered under the
 * `sessionRequirements` kind so the full set exercises the kind through the
 * template's boot (ADR 2026-09-28-session-admission): one with a page (a
 * step-up's shape, over an empty reach) and one bare. Each admits every use
 * and interrupts the login of the subjects in `interrupt` alone, so the full
 * set's own logins run uninterrupted.
 *
 * Each also acts as a requirement's module at establishment. Its interruption
 * records the ceremony it opens (bound to the regenerated express session,
 * with the continuation core built) in its own record, here memory. Its
 * completion route, `POST <FIXTURE_COMPLETION>/complete` on that session,
 * spends the ceremony whatever the resumption answers, completes it adding
 * nothing (`amr: []`), resumes the login through `resumePrimary` (which does
 * not ask a requirement already done in that login again, so a fixture
 * interrupts every login it is asked about), and answers what admission
 * answers through the session package's exports: another requirement's
 * interruption (`answerInterruption`) or the session established
 * (`establishSession`). Every ceremony opened is pushed on `ceremonies`;
 * `failAskOnce` makes one requirement's next ask an outage.
 *
 * A sketch, not a route to copy: the real one (the MFA package's) sits
 * behind the session's CSRF guard, projects every error it logs, and answers
 * a `RangeError` from `resumePrimary` (a continuation naming a requirement a
 * deploy removed, say) as "log in again".
 */
function requirementModules(
	interrupt: ReadonlySet<string>,
	ceremonies: FixtureCeremony[],
	outage: { once: FixtureCeremony["requirement"] | undefined },
): Module[] {
	// Neither reaches anything: only the requirement that declares the
	// second-factor authority may declare a non-empty reach, and a page may
	// still stand with an empty one (a step-up that adds no value).
	const noReach: ReadonlySet<string> = new Set();
	const fixture = (spec: {
		readonly module: string;
		readonly name: FixtureCeremony["requirement"];
		readonly key: keyof typeof FIXTURE_COMPLETION;
		readonly stepUpPage: SessionRequirement["stepUpPage"];
		readonly remediations: readonly string[];
		readonly hintKeys: readonly string[];
	}): Module => {
		const answer: InterruptionAnswer = FIXTURE_INTERRUPTION[spec.key];
		/** The requirement's own record: each open ceremony by the session it is bound to. */
		const opened = new Map<string, PrimaryContinuation>();
		const interruption: RequirementInterruption = {
			open: async (sessionId, continuation) => {
				opened.set(sessionId, continuation);
				ceremonies.push({ requirement: spec.name, sessionId, continuation });
				return answer;
			},
		};
		return defineModule<
			"config" | "userSessionStore" | "sessionRequirementResolver" | "csrfGuard",
			"subjectSessionIndex" | "logger"
		>({
			name: spec.module,
			requires: ["config", "userSessionStore", "sessionRequirementResolver", "csrfGuard"],
			optional: ["subjectSessionIndex", "logger"],
			absencePolicies: { subjectSessionIndex: SUBJECT_REVOCATION_ABSENCE_POLICY },
			contributes: {
				sessionRequirements: {
					[spec.name]: (): SessionRequirement => ({
						name: spec.name,
						get reach() {
							return noReach;
						},
						stepUpPage: spec.stepUpPage,
						remediations: spec.remediations,
						hintKeys: spec.hintKeys,
						admit: async () => ({ outcome: "met" }),
						admitPrimary: async (primary: PrimaryAuthentication) => {
							// The outage a test asks for, once: the requirement's own
							// store cannot answer (admission answers `unavailable`).
							if (outage.once === spec.name) {
								outage.once = undefined;
								throw new Error(`${spec.name}: the requirement's store is down`);
							}
							return interrupt.has(primary.subject) ? interruption : "establish";
						},
					}),
				},
				routes: [
					(deps) => {
						const config = deps.config as AppConfig;
						const logger = deps.logger ?? consoleLogger;
						// The deployment's CSRF guard: an interruption's fresh token is
						// the one the login router and every guarded route accept.
						const csrf = deps.csrfGuard;
						const admissionDeps: AdmissionDeps = {
							userSessionStore: deps.userSessionStore,
							subjectRevocation: undefined,
							requirements: deps.sessionRequirementResolver,
							acrTable: {},
							logger,
							auditSink: undefined,
						};
						// `POST <mountPath>/complete`, and nothing else beneath the path.
						const complete: RequestHandler = async (req, res, next) => {
							if (req.method !== "POST" || req.path !== "/complete") {
								next();
								return;
							}
							// The ceremony bound to the session this browser holds; spent here.
							const continuation = opened.get(req.sessionID);
							if (continuation === undefined) {
								res.status(400).json({ error: "invalid_request" });
								return;
							}
							opened.delete(req.sessionID);
							const admission = await resumePrimary(admissionDeps, continuation, {
								requirement: spec.name,
								adds: { amr: [] },
							});
							if (admission.outcome === "unavailable") {
								res.status(503).json(FIXTURE_UNAVAILABLE);
								return;
							}
							if (admission.outcome === "interrupt") {
								// As the login answers one: regenerate, open, save, the 403.
								await answerInterruption(admission, {
									req,
									res,
									csrf,
									reporter: {
										storeUnavailable: (store, step, cause) =>
											logger.error(
												{ store, step, err: loggableError(cause) },
												"fixture_completion_unavailable",
											),
									},
								});
								return;
							}
							const established = await establishSession(admission.establishment, {
								req,
								userSessionStore: deps.userSessionStore,
								...(deps.subjectSessionIndex
									? { subjectSessionIndex: deps.subjectSessionIndex }
									: {}),
								sessionTtlMs: config.session.maxAge,
								reporter: () => ({
									storeUnavailable: (store, step, cause) =>
										logger.error(
											{ store, step, err: loggableError(cause) },
											"fixture_completion_unavailable",
										),
									cleanupFailed: (store, step, cause) =>
										logger.warn(
											{ store, step, err: loggableError(cause) },
											"fixture_completion_cleanup_failed",
										),
									subjectIndexWriteFailed: (cause) =>
										logger.error(
											{ err: loggableError(cause) },
											"subject_session_index_write_failed",
										),
								}),
							});
							if (established.outcome === "unavailable") {
								res.status(503).json(FIXTURE_UNAVAILABLE);
								return;
							}
							res.status(200).json({ message: "Logged in successfully" });
						};
						return {
							id: `fixture-${spec.key}-completion`,
							mountPath: FIXTURE_COMPLETION[spec.key],
							after: ["session-middleware"],
							handler: complete,
						};
					},
				],
			},
		});
	};
	return [
		fixture({
			module: "deployment:requirement-page",
			name: "fixture-page",
			key: "page",
			stepUpPage: { url: "/fixture/step-up", params: { requirement: "fixture-page" } },
			remediations: ["fixture-page.step_up"],
			hintKeys: ["fixture_hint"],
		}),
		fixture({
			module: "deployment:requirement-bare",
			name: "fixture-bare",
			key: "bare",
			stepUpPage: undefined,
			remediations: [],
			hintKeys: [],
		}),
	];
}

/**
 * Stands in for the deployment's own WebAuthn credential store on several
 * replicas: no package ships a shared one, and the README has a production
 * deployment wire its own database. Boot cannot tell it from a database, which
 * is the point — what `multi` refuses is the bundled memory module, by name.
 */
const deploymentCredentialStoreModule = defineModule({
	name: "deployment:webauthn-credential-store",
	provides: {
		webauthnCredentialStore: () => createMemoryWebAuthnCredentialStore(),
	},
});

export interface Fakes {
	readonly apple: FakeIdp;
	readonly github: FakeGithub;
}

let fakes: Promise<{ fakes: Fakes; reset: () => void }> | undefined;

/**
 * The Apple and GitHub fakes, made once per test file, shared by every boot,
 * and put back as they were made before each one.
 */
export async function sharedFakes(): Promise<Fakes> {
	fakes ??= createFakes().then((made) => ({
		fakes: made,
		reset: resettable(made.apple, made.github),
	}));
	const { fakes: made, reset } = await fakes;
	reset();
	return made;
}

async function createFakes(): Promise<Fakes> {
	return {
		// Apple's endpoints are fixed in the adapter, not discovered.
		apple: await createFakeIdp({
			issuer: "https://appleid.apple.com",
			authorizationEndpoint: "https://appleid.apple.com/auth/authorize",
			tokenEndpoint: "https://appleid.apple.com/auth/token",
			jwksUri: "https://appleid.apple.com/auth/keys",
			clientId: "com.example.composition",
			sub: APPLE_SUB,
		}),
		github: createFakeGithub(),
	};
}

/** The subjects the Apple and GitHub fakes sign in, as the Store has them linked. */
const APPLE_SUB = "000123.apple-composition.0456";
const GITHUB_ID = 12345;

/** A federation section's fields, as the bridges read them (they check nothing else). */
const section = (config: AppConfig, name: string): Record<string, string> =>
	(config.federations as Record<string, Record<string, string>>)[name] ?? {};

function federationBridges(config: AppConfig, features: Features, f: Fakes): Module[] {
	const bridge = (name: "apple" | "github", fetch: typeof globalThis.fetch) => {
		const { clientId, clientSecret, callbackURL, clientUrl } = section(config, name);
		return defineModule({
			name: `deployment:${name}-federation-config`,
			provides: {
				[`${name}FederationConfig`]: () => ({
					clientId,
					clientSecret,
					callbackURL,
					clientUrl,
					fetch,
				}),
			},
		});
	};
	return [
		...(features.apple ? [appleFederationModule, bridge("apple", f.apple.fetch)] : []),
		...(features.github ? [githubFederationModule, bridge("github", f.github.fetch)] : []),
	];
}

/** The store behind each added feature that keeps state. */
interface AddedStores {
	readonly deviceCode: Stores;
	readonly challenge: Stores;
	readonly credential: Module;
	readonly mfa: Stores;
}

/** Every module the template does not compose, as a deployment adds them to its manifest. */
function addedModules(
	config: AppConfig,
	features: Features,
	stores: AddedStores,
	f: Fakes,
	interrupt: ReadonlySet<string>,
	ceremonies: FixtureCeremony[],
	outage: { once: FixtureCeremony["requirement"] | undefined },
): Module[] {
	return [
		deviceGrantModule({ config }),
		stores.deviceCode === "redis" ? redisDeviceCodeStoreModule : memoryDeviceCodeStoreModule,
		dpopModule,
		mtlsModule,
		...(features.tokenExchange ? [tokenExchangeModule] : []),
		...(features.webauthn
			? [
					webauthnModule,
					webauthnConfigModule,
					webauthnSubjectModule,
					stores.credential,
					stores.challenge === "redis" ? redisChallengeStoreModule : memoryChallengeStoreModule,
					defaultChallengeCeremonyModule,
				]
			: []),
		// The MFA package: the TOTP factor, on by its reference.conf, the
		// recovery-code factor's module, and the MFA module, which registers
		// the requirement named mfa, over the two MFA stores. The environment
		// is the one the template composes as.
		...(features.mfa
			? [
					...mfaModules({ environment: "production" }),
					...(stores.mfa === "redis"
						? [redisMfaFactorStoreModule, redisMfaTransactionStoreModule]
						: [memoryMfaFactorStoreModule, memoryMfaTransactionStoreModule]),
				]
			: []),
		grantPolicyModule,
		...requirementModules(interrupt, ceremonies, outage),
		...federationBridges(config, features, f),
	];
}

// ---------------------------------------------------------------------------
// Registrations
// ---------------------------------------------------------------------------

export const TV = { id: "tv" } as const;
export const GATEWAY = { id: "gateway", secret: "gateway-secret" } as const;
export const BINDER = { id: "binder", secret: "binder-secret" } as const;
/** BINDER's twin that requires a sender constraint — every token it gets is bound. */
export const REQUIRED_BINDER = { id: "required-binder", secret: "required-binder-secret" } as const;

const EXTRA_CLIENTS: Readonly<Record<string, Record<string, unknown>>> = {
	// A public device client.
	[TV.id]: {
		tokenEndpointAuthMethod: "none",
		allowedScopes: ["openid"],
		defaultScopes: ["openid"],
		allowedGrantTypes: [DEVICE_CODE_GRANT_TYPE],
	},
	// A confidential client exchanging the web client's tokens for its own.
	// `email` and the federation-token allowlist are there so what an
	// exchanged token must NOT reach — the session's claims at /userinfo, the
	// upstream token — is within the client's registration: only the missing
	// session capability stands in the way.
	[GATEWAY.id]: {
		tokenEndpointAuthMethod: "client_secret_basic",
		clientSecret: GATEWAY.secret,
		allowedScopes: ["openid", "profile", "email"],
		allowedAudiences: [ISSUER],
		allowedGrantTypes: [TOKEN_EXCHANGE_GRANT_TYPE],
		allowedAzpForFederationToken: true,
	},
	// A machine client whose tokens are sender-constrained by DPoP or mTLS.
	[BINDER.id]: {
		tokenEndpointAuthMethod: "client_secret_basic",
		clientSecret: BINDER.secret,
		allowedScopes: ["api.read"],
		defaultScopes: ["api.read"],
		allowedGrantTypes: ["client_credentials"],
	},
	// The same, registered to require a binding by either mechanism: the
	// dispatch gate must let each real mechanism's binding through.
	[REQUIRED_BINDER.id]: {
		tokenEndpointAuthMethod: "client_secret_basic",
		clientSecret: REQUIRED_BINDER.secret,
		allowedScopes: ["api.read"],
		defaultScopes: ["api.read"],
		allowedGrantTypes: ["client_credentials"],
		senderConstrained: { required: true, methods: ["dpop", "mtls"] },
	},
};

const EXTRA_USERS: Readonly<Record<string, Record<string, unknown>>> = {
	carol: { id: "u-carol", password: "carol-password-long", token: `apple:${APPLE_SUB}` },
	dave: { id: "u-dave", password: "dave-password-long", token: `github:${GITHUB_ID}` },
};

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

export interface FullSetOptions extends Omit<ComposeOptions, "extraModules" | "referenceConfs"> {
	readonly features?: Partial<Features>;
	/** The added features' stores: memory (the default), or Redis on the template's shared socket. */
	readonly stores?: Stores;
	/** One store's adapter against the rest (a replica-safety case). */
	readonly deviceCodeStore?: Stores;
	readonly challengeStore?: Stores;
	/** The two MFA stores' adapter against the rest. */
	readonly mfaStores?: Stores;
	/**
	 * The WebAuthn credential store module. Default: core's memory module on
	 * memory stores, the deployment's own on Redis (no package ships a shared
	 * one).
	 */
	readonly credentialStore?: Module;
	/** Adjust the resolved config after the features are laid over it. */
	readonly adjust?: (config: AppConfig) => AppConfig;
	/** The subjects whose login both fixture requirements interrupt; none by default. */
	readonly interruptLogins?: readonly string[];
	/** Where the fixture requirements record each ceremony they open; a list of the boot's own by default. */
	readonly ceremonies?: FixtureCeremony[];
	/** A fixture requirement whose next `admitPrimary` throws, once: an outage of its own store. */
	readonly failAskOnce?: FixtureCeremony["requirement"];
}

export interface FullSet extends Composition {
	readonly fakes: Fakes;
}

/** The template's composition options for the full set. */
export async function fullSetOptions(options: FullSetOptions = {}): Promise<ComposeOptions> {
	const features = { ...ALL_ON, ...options.features };
	const stores = options.stores ?? "memory";
	const f = await sharedFakes();
	const added: AddedStores = {
		deviceCode: options.deviceCodeStore ?? stores,
		challenge: options.challengeStore ?? stores,
		mfa: options.mfaStores ?? stores,
		credential:
			options.credentialStore ??
			(stores === "redis" ? deploymentCredentialStoreModule : memoryWebAuthnCredentialStoreModule),
	};
	const {
		features: _features,
		stores: _stores,
		deviceCodeStore: _deviceCodeStore,
		challengeStore: _challengeStore,
		mfaStores: _mfaStores,
		credentialStore: _credentialStore,
		adjust: _adjust,
		interruptLogins,
		ceremonies,
		failAskOnce,
		...compose
	} = options;
	const interrupt = new Set(interruptLogins ?? []);
	const opened = ceremonies ?? [];
	const outage = { once: failAskOnce };
	return {
		...compose,
		config: (resolved) => {
			const adjusted = options.config ? options.config(resolved) : resolved;
			const featured = withFeatures(adjusted, features);
			return options.adjust ? options.adjust(featured) : featured;
		},
		extraModules: (config) => addedModules(config, features, added, f, interrupt, opened, outage),
		extraClients: { ...EXTRA_CLIENTS, ...options.extraClients },
		extraUsers: { ...EXTRA_USERS, ...options.extraUsers },
	};
}

/** Boots the full set: the template's composition, every other package added. */
export async function composeFullSet(options: FullSetOptions = {}): Promise<FullSet> {
	const composition = await compose(await fullSetOptions(options));
	return { ...composition, fakes: await sharedFakes() };
}

export { deploymentCredentialStoreModule, memoryWebAuthnCredentialStoreModule };

// ---------------------------------------------------------------------------
// Sender constraints
// ---------------------------------------------------------------------------

const dpopKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
const { kty, crv, x, y } = dpopKey.publicKey.export({ format: "jwk" });
export const DPOP_JWK = { kty, crv, x, y } as const;

const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");

/** An RFC 9449 proof for `htm` `htu`, signed ES256 under the one test key. */
export function dpopProof(htm: string, htu: string, claims: Record<string, unknown> = {}): string {
	const input = `${b64({ typ: "dpop+jwt", alg: "ES256", jwk: DPOP_JWK })}.${b64({
		htm,
		htu,
		iat: Math.floor(Date.now() / 1000),
		jti: randomUUID(),
		...claims,
	})}`;
	const signature = sign("sha256", Buffer.from(input), {
		key: dpopKey.privateKey,
		dsaEncoding: "ieee-p1363",
	});
	return `${input}.${signature.toString("base64url")}`;
}
