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
	BootError,
	createApp,
	createInMemoryUserSessionStore,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	createMemoryRateLimiter,
	defineModule,
	type FederationTokenStore,
	InMemoryUserRepository,
	type MfaFactorStore,
	type MfaTransactionStore,
	type Module,
	type SessionFederationIndex,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { sessionModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";
import express from "express";
import request from "supertest";
import { type Mock, vi } from "vitest";
import { type MfaModuleOptions, mfaModule, mfaModules } from "#/module.mjs";

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
export const LOCKOUT = {
	threshold: 5,
	baseSeconds: 900,
	maxSeconds: 86_400,
	memorySeconds: 86_400,
	weeklyBudget: 10,
	hardLimit: 100,
	trustedBrowsers: 5,
	trustedBrowserDays: 30,
} as const;

/** The `mfa` section as the package's reference.conf resolves it, under `mode`, with this suite's key. */
export const mfaSection = (mode: "off" | "optional" | "required") => ({
	mode,
	encryptionKeys: [{ key: MFA_KEY }],
	transactionTtlSeconds: 600,
	maxAttemptsPerTransaction: 5,
	lockout: { ...LOCKOUT },
});

/** The TOTP factor's `mfa-totp-factor` section as the package's reference.conf resolves it. */
export const TOTP_SECTION = {
	enabled: true,
	algorithm: "SHA1",
	digits: 6,
	period: 30,
	window: 1,
} as const;

/**
 * The composition's configuration: core's valid fixture, a login over plain
 * HTTP (no `Secure` cookie), `endpoints.mfa.url` as core's reference.conf
 * ships it, `mfa` declared expected, the `mfa` section under `mode`, and the
 * TOTP factor's `mfa-totp-factor` section, each with the keys given laid
 * over it.
 */
export function configFor(
	mode: "off" | "optional" | "required",
	mfa: Record<string, unknown> = {},
	totp: Record<string, unknown> = {},
): AppConfig {
	const base = makeValidAppConfig();
	return {
		...base,
		oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: ISSUER } },
		session: {
			...base.session,
			name: "auth.session",
			secure: false,
			redirectAllowlist: ["https://app.example/after"],
		},
		endpoints: { ...base.endpoints, mfa: { url: "/mfa" } },
		sessionRequirements: { expected: ["mfa"] },
		mfa: { ...mfaSection(mode), ...mfa },
		"mfa-totp-factor": { ...TOTP_SECTION, ...totp },
	} as unknown as AppConfig;
}

const providing = (name: string, provides: Record<string, () => unknown>): Module =>
	defineModule({ name, provides: provides as never });

/** The session package's stores the login module requires beside the user-session store; unused here. */
const sessionSupport = (): Module[] => [
	providing("test:user-repository", {
		userRepository: () =>
			new InMemoryUserRepository(
				new Map([[ALICE.username, { password: ALICE.password, id: ALICE.id, email: ALICE.email }]]),
			),
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
	providing("test:rate-limiter", {
		rateLimiter: () =>
			createMemoryRateLimiter({ limits: {}, defaultLimit: { limit: 1000, windowSeconds: 60 } }),
	}),
];

export interface BootOptions {
	readonly config?: AppConfig;
	readonly options?: MfaModuleOptions;
	readonly factorStore?: MfaFactorStore;
	readonly transactionStore?: MfaTransactionStore;
	readonly userSessionStore?: UserSessionStore | null;
	/** Modules beside the composition's: another factor, say. */
	readonly extraModules?: readonly Module[];
	/** Leave the session package's login out: the MFA modules and their stores alone. */
	readonly withoutLogin?: boolean;
	/** Install `mfaModule` alone, without the TOTP factor's module: a composition whose factors are all another package's. */
	readonly withoutTotpModule?: boolean;
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
	return {
		modules: [
			...(options.withoutLogin === true
				? []
				: [sessionStoreModuleFor(config as never), sessionModule, ...sessionSupport()]),
			...(userSessionStore === null
				? []
				: [providing("test:user-session-store", { userSessionStore: () => userSessionStore })]),
			providing("test:mfa-factor-store", { mfaFactorStore: () => factorStore }),
			providing("test:mfa-transaction-store", { mfaTransactionStore: () => transactionStore }),
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
		bootstrapComponents: { config, pathResolver: (s: string) => s, logger } as never,
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

/** `POST /session/login` as a browser: a CSRF token first, then the credentials, on one cookie jar. */
export async function login(
	app: express.Express,
	body: Record<string, unknown> = {},
): Promise<{ readonly agent: ReturnType<typeof request.agent>; readonly res: request.Response }> {
	const agent = request.agent(app);
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
