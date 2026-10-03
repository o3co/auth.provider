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
 * The composition the MFA module's suites boot through `createApp`: the
 * session package's login (its module and express-session's in-memory
 * store), the MFA package's modules, core's memory MFA stores — or stores a
 * test holds, to seed a factor or make one fail — the user `alice` in the
 * bundled in-memory directory, and a logger whose every level is a spy. Not
 * a test file.
 */

import { randomBytes } from "node:crypto";
import {
	type AppConfig,
	type AuditSink,
	BootError,
	createApp,
	createInMemoryUserSessionStore,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	createMemoryRateLimiter,
	defineModule,
	type FederationTokenStore,
	InMemoryUserRepository,
	type MailSender,
	type MfaFactorStore,
	type MfaTransactionStore,
	type Module,
	type RateLimiter,
	type SessionFederationIndex,
	type SubjectRevocation,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	CORE_RELOCATIONS,
	coreConfigForTests,
	createRecordingLoginCompletion,
	createTestCsrfGuard,
	createTestOAuthTokenSettings,
	makeValidAppConfig,
	renamedVariableCaptures,
} from "@o3co/auth-provider-core/testing";
import {
	loginCompletionModule,
	sessionModule,
	sessionStoreModule,
	sessionStoreModuleFor,
} from "@o3co/auth-provider-session";
import express from "express";
import request from "supertest";
import { type Mock, vi } from "vitest";
import { type MfaModuleOptions, mfaModule, mfaModules } from "#/module.mjs";
import {
	type MfaConfigForTestsOptions,
	type MfaTotpFactorConfigForTestsOptions,
	mfaConfigForTests,
	mfaEmailFactorConfigForTests,
	mfaRecoveryCodeFactorConfigForTests,
	mfaTotpFactorConfigForTests,
} from "#/testing/index.mjs";
import { mfaTotpFactorModule } from "#/totp/module.mjs";

export const ISSUER = "https://auth.example";

/** A key of this suite's own: never the development sample key. */
export const MFA_KEY = randomBytes(32).toString("base64");

/** The user the directory verifies. */
export const ALICE = {
	username: "alice",
	password: "alice-password-long",
	id: "u-alice",
	email: "alice@example.com",
} as const;

/** A second user the directory verifies. */
export const BOB = {
	username: "bob",
	password: "bob-password-long",
	id: "u-bob",
	email: "bob@example.com",
} as const;

/** A logger whose every level is a spy; `child` answers the same logger. */
export interface SpyLogger {
	readonly trace: Mock;
	readonly debug: Mock;
	readonly info: Mock;
	readonly warn: Mock;
	readonly error: Mock;
	readonly fatal: Mock;
	readonly child: Mock;
}

/** A {@link SpyLogger}. */
export function spyLogger(): SpyLogger {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(),
	};
	logger.child.mockReturnValue(logger);
	return logger;
}

/** The lines logged at `level`, by event name. */
export const events = (logger: SpyLogger, level: "info" | "warn" | "error"): string[] =>
	logger[level].mock.calls.map((call) => call[1] as string);

/**
 * `mfa.lockout` at its defaults (ADR 2026-09-25-multi-factor-authentication,
 * D19 and D21).
 */
export const LOCKOUT = mfaConfigForTests({ key: MFA_KEY }).mfa.lockout;

/** The `mfa` section as the package's reference.conf resolves it, under `mode`, with this suite's key. */
export const mfaSection = (mode: "off" | "optional" | "required") =>
	mfaConfigForTests({ key: MFA_KEY, mode }).mfa;

/** The recovery-code factor's `mfa-recovery-code-factor` section as the package's reference.conf resolves it. */
export const RECOVERY_CODE_SECTION =
	mfaRecoveryCodeFactorConfigForTests()["mfa-recovery-code-factor"];

/** The TOTP factor's `mfa-totp-factor` section as the package's reference.conf resolves it. */
export const TOTP_SECTION = mfaTotpFactorConfigForTests()["mfa-totp-factor"];

/**
 * What a composition layering the package's reference.conf and core's
 * captures of the MFA modules' renamed variables, the session package's
 * modules' and core's own, under an environment that sets none.
 */
export const UNSET_RENAMED_VARIABLES = renamedVariableCaptures({
	modules: [mfaTotpFactorModule, mfaModule(), sessionModule, sessionStoreModule],
	core: CORE_RELOCATIONS,
	env: {},
});

/**
 * The composition's configuration: core's valid fixture, a login over plain
 * HTTP (no `Secure` cookie), `expected` declared (`mfa` alone by default), the `mfa` section under
 * `mode`, and the TOTP factor's `mfa-totp-factor` section, each with the keys
 * given laid over it, the recovery-code and email factors' sections as their
 * defaults, and the captures of the renamed variables, all unset.
 */
export function configFor(
	mode: "off" | "optional" | "required",
	mfa: Record<string, unknown> = {},
	totp: Record<string, unknown> = {},
	expected: readonly string[] = ["mfa"],
): AppConfig {
	const base = makeValidAppConfig();
	return {
		...base,
		oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: ISSUER } },
		"session-store": { ...base["session-store"], name: "auth.session", secure: false },
		session: { ...base.session, redirectAllowlist: ["https://app.example/after"] },
		...coreConfigForTests({ expected, declaredAbsent: ["auditSink"] }),
		...mfaConfigForTests({ key: MFA_KEY, mode, ...(mfa as Partial<MfaConfigForTestsOptions>) }),
		...mfaTotpFactorConfigForTests(totp as MfaTotpFactorConfigForTestsOptions),
		...mfaRecoveryCodeFactorConfigForTests(),
		...mfaEmailFactorConfigForTests(),
		"renamed-variables": UNSET_RENAMED_VARIABLES,
	} as unknown as AppConfig;
}

const providing = (name: string, provides: Record<string, () => unknown>): Module =>
	defineModule({ name, provides: provides as never });

/**
 * The `oauthTokenSettings` slot holding `issuer` — {@link ISSUER} unless
 * given — which the TOTP factor's module requires for the deployment's
 * issuer: what the oauth module provides in a deployment.
 */
export const oauthTokenSettingsFor = (issuer: string = ISSUER): Module =>
	providing("test:oauth-token-settings", {
		oauthTokenSettings: () => createTestOAuthTokenSettings({ issuer }),
	});

/** A limiter that allows what a test sends: every prefix well above any test's traffic. */
const generousRateLimiter = (): RateLimiter =>
	createMemoryRateLimiter({ limits: {}, defaultLimit: { limit: 1000, windowSeconds: 60 } });

/**
 * The session package's stores the login module requires beside the
 * user-session store, and the directory; `rateLimiter` is the composition's
 * limiter, none when `null`.
 */
/** The directory the login verifies: alice and bob, each with an address. */
export const directoryEntries = () =>
	new Map<string, Record<string, unknown> & { password: string }>([
		[ALICE.username, { password: ALICE.password, id: ALICE.id, email: ALICE.email }],
		[BOB.username, { password: BOB.password, id: BOB.id, email: BOB.email }],
	]);

/** A directory that writes the enrollment witness: each mark recorded, and answered back by the next `authenticate`. */
export class WitnessingUserRepository extends InMemoryUserRepository {
	/** Every mark written, oldest first. */
	readonly marks: { readonly subject: string; readonly enrolled: boolean }[] = [];
	private failure: unknown;

	constructor(private readonly entries = directoryEntries()) {
		super(entries);
	}

	/** From now on, every mark rejects with `error` and writes nothing. */
	failWith(error: unknown): void {
		this.failure = error;
	}

	/** Write marks again. */
	recover(): void {
		this.failure = undefined;
	}

	async markMfaEnrolled(subject: string, enrolled: boolean): Promise<void> {
		if (this.failure !== undefined) throw this.failure;
		this.marks.push({ subject, enrolled });
		for (const entry of this.entries.values()) {
			if (entry.id === subject) entry.mfaEnrolled = enrolled;
		}
	}
}

const sessionSupport = (
	rateLimiter: RateLimiter | null,
	userRepository: UserRepository | undefined,
): Module[] => [
	providing("test:user-repository", {
		userRepository: () => userRepository ?? new WitnessingUserRepository(),
	}),
	providing("test:federation-token-store", {
		federationTokenStore: () =>
			({
				kind: "memory",
				attach: async () => {},
				get: async () => null,
				update: async () => {},
				removeBySid: async () => {},
				delete: async () => {},
			}) as unknown as FederationTokenStore,
	}),
	providing("test:session-federation-index", {
		sessionFederationIndex: () =>
			({
				kind: "memory",
				addFederation: async () => {},
				listFederations: async () => [],
				removeFederation: async () => {},
				removeBySid: async () => {},
			}) as unknown as SessionFederationIndex,
	}),
	...(rateLimiter === null
		? []
		: [providing("test:rate-limiter", { rateLimiter: () => rateLimiter })]),
];

/**
 * What the MFA module requires of the session package, in a composition
 * without its login: core's doubles for the CSRF guard and the login's
 * completion.
 */
const loginStandIns = (): Module =>
	providing("test:login-stand-ins", {
		csrfGuard: () => createTestCsrfGuard(),
		loginCompletion: () => createRecordingLoginCompletion(),
	});

export interface BootOptions {
	readonly config?: AppConfig;
	readonly options?: MfaModuleOptions;
	readonly factorStore?: MfaFactorStore;
	readonly transactionStore?: MfaTransactionStore;
	readonly userSessionStore?: UserSessionStore | null;
	/** The composition's rate limiter; one that allows every test's traffic by default, none when `null`. */
	readonly rateLimiter?: RateLimiter | null;
	/** Where the composition's audit events go; the configuration declares none by default. */
	readonly auditSink?: AuditSink;
	/** The composition's mail sender; none by default. */
	readonly mailSender?: MailSender;
	/** The directory the login verifies; alice and bob in a {@link WitnessingUserRepository} by default. */
	readonly userRepository?: UserRepository;
	/** The subjects' revocation boundary; none by default, its absence declared by the configuration. */
	readonly subjectRevocation?: SubjectRevocation;
	/** Modules beside the composition's: another factor, say. */
	readonly extraModules?: readonly Module[];
	/** Leave the session package's login out: the MFA modules and their stores alone. */
	readonly withoutLogin?: boolean;
	/** Load the session package's login without its login-completion module. */
	readonly withoutLoginCompletion?: boolean;
	/** Install `mfaModule` alone, without the TOTP factor's module: a composition whose factors are all another package's. */
	readonly withoutTotpModule?: boolean;
	/**
	 * The deployment's issuer the `oauthTokenSettings` slot holds, {@link ISSUER}
	 * by default; `null`, and no module provides the slot.
	 */
	readonly tokenIssuer?: string | null;
	readonly logger?: SpyLogger;
}

export interface Booted {
	readonly handle: Awaited<ReturnType<typeof createApp>>;
	readonly app: express.Express;
	readonly logger: SpyLogger;
	readonly factorStore: MfaFactorStore;
	readonly transactionStore: MfaTransactionStore;
	readonly userSessionStore: UserSessionStore | null;
}

/** The modules of the composition `options` describes. */
export function modulesFor(options: BootOptions = {}): {
	readonly modules: Module[];
	readonly factorStore: MfaFactorStore;
	readonly transactionStore: MfaTransactionStore;
	readonly userSessionStore: UserSessionStore | null;
} {
	const config = options.config ?? configFor("required");
	const factorStore = options.factorStore ?? createMemoryMfaFactorStore();
	const transactionStore = options.transactionStore ?? createMemoryMfaTransactionStore();
	const userSessionStore =
		options.userSessionStore === undefined
			? createInMemoryUserSessionStore()
			: options.userSessionStore;
	const rateLimiter =
		options.rateLimiter === undefined ? generousRateLimiter() : options.rateLimiter;
	return {
		modules: [
			...(options.withoutLogin === true
				? [loginStandIns()]
				: [
						sessionStoreModuleFor(config as never),
						sessionModule,
						...(options.withoutLoginCompletion === true ? [] : [loginCompletionModule]),
						...sessionSupport(rateLimiter, options.userRepository),
					]),
			...(options.mailSender === undefined
				? []
				: [providing("test:mail-sender", { mailSender: () => options.mailSender })]),
			...(options.subjectRevocation === undefined
				? []
				: [
						providing("test:subject-revocation", {
							subjectRevocation: () => options.subjectRevocation,
						}),
					]),
			...(userSessionStore === null
				? []
				: [providing("test:user-session-store", { userSessionStore: () => userSessionStore })]),
			providing("test:mfa-factor-store", { mfaFactorStore: () => factorStore }),
			providing("test:mfa-transaction-store", { mfaTransactionStore: () => transactionStore }),
			...(options.tokenIssuer === null ? [] : [oauthTokenSettingsFor(options.tokenIssuer)]),
			...(options.withoutTotpModule === true
				? [mfaModule(options.options ?? { environment: "development" })]
				: mfaModules(options.options ?? { environment: "development" })),
			...(options.extraModules ?? []),
		],
		factorStore,
		transactionStore,
		userSessionStore,
	};
}

const handles: { dispose(): Promise<void> }[] = [];

/** Disposes every composition booted since the last call. */
export const disposeAll = async (): Promise<void> => {
	await Promise.all(handles.splice(0).map((handle) => handle.dispose()));
};

/** Boots the composition; `disposeAll` disposes it. */
export async function boot(options: BootOptions = {}): Promise<Booted> {
	const logger = options.logger ?? spyLogger();
	const config = options.config ?? configFor("required");
	const composed = modulesFor({ ...options, config });
	const handle = await createApp({
		modules: composed.modules,
		bootstrapComponents: {
			config,
			pathResolver: (s: string) => s,
			logger,
			...(options.auditSink === undefined ? {} : { auditSink: options.auditSink }),
		} as never,
	});
	handles.push(handle);
	const app = express();
	app.use(handle.router);
	return { handle, app, logger, ...composed };
}

/** Boots the composition expecting the planner to refuse it, and answers the refusal. */
export async function refusal(options: BootOptions = {}): Promise<BootError> {
	try {
		await boot(options);
	} catch (err) {
		if (err instanceof BootError) return err;
		throw err;
	}
	throw new Error("the composition booted");
}

/** `POST /session/login` as a browser: a CSRF token first, then the credentials, on one cookie jar; alice's unless `body` names another. */
export async function login(
	app: express.Express,
	body: Record<string, unknown> = {},
	agent: ReturnType<typeof request.agent> = request.agent(app),
): Promise<{ readonly agent: ReturnType<typeof request.agent>; readonly res: request.Response }> {
	const csrf = await agent.get("/session/csrf");
	const res = await agent
		.post("/session/login")
		.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
		.send({ username: ALICE.username, password: ALICE.password, ...body });
	return { agent, res };
}

/** The express session id a response's `Set-Cookie` hands the browser: the signed cookie's value, unsigned. */
export function sessionIdSet(res: request.Response): string | undefined {
	const cookies = ([] as string[]).concat(res.headers["set-cookie"] ?? []);
	const cookie = cookies.find((line) => line.startsWith("auth.session="));
	if (cookie === undefined) return undefined;
	const value = decodeURIComponent(cookie.slice("auth.session=".length).split(";")[0] as string);
	// express-session signs it as `s:<id>.<signature>`.
	return value.startsWith("s:") ? value.slice(2, value.lastIndexOf(".")) : undefined;
}
