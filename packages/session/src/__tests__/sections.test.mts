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
 * The package's sections: the session module's `session {}` (the redirect
 * allowlist, the CSRF policy, the login page and the login's rate-limit
 * budget) and the session store's `session-store {}` (the session cookie, the
 * secret that signs it, and the store express-session keeps sessions in),
 * with their defaults in the package's `config/reference.conf`. A path they
 * moved from refuses boot naming the new one, and a variable renamed with
 * them refuses boot unless its new name carries the same value.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
	type AppConfig,
	BootError,
	createApp,
	defineModule,
	type FederationTokenStore,
	MAX_DURATION_MS,
	moduleReferences,
	type SessionFederationIndex,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig, packageReferenceProblems } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { sessionModule, sessionSectionSchema } from "#/module.mjs";
import {
	sessionStoreConfigSchema,
	sessionStoreModule,
	sessionStoreModuleFor,
} from "#/modules/sessionStoreModule.mjs";
import { withSession, withSessionCaptures, withStore } from "./_helpers/sections.mjs";

/** The package's defaults, as a composition root finds them. */
const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

const MARKER = "__SESSION_REFERENCE_MARKER__";

/** Every path in `tree` whose value is the marker. */
function markedPaths(tree: unknown, prefix = ""): string[] {
	if (typeof tree === "object" && tree !== null && !Array.isArray(tree)) {
		return Object.entries(tree).flatMap(([key, value]) =>
			markedPaths(value, prefix === "" ? key : `${prefix}.${key}`),
		);
	}
	return tree === MARKER ? [prefix] : [];
}

/** Each path the file binds a variable at, as `VARIABLE at path`. */
function bindings(): string[] {
	const file = fileURLToPath(REFERENCE);
	const variables = [
		...new Set(
			[...readFileSync(file, "utf8").matchAll(/\$\{\??([A-Za-z0-9_]+)\}/g)].map((match) =>
				String(match[1]),
			),
		),
	];
	return variables.flatMap((variable) =>
		markedPaths(parseFile(file, { env: { [variable]: MARKER } }).toObject()).map(
			(path) => `${variable} at ${path}`,
		),
	);
}

/** The package's reference, resolved with no variable set. */
const defaults = (): Record<string, unknown> =>
	parseFile(fileURLToPath(REFERENCE), { env: {} }).toObject() as Record<string, unknown>;

/** Each renamed variable: [old name, new name, old path, new path]. */
const RENAMED = [
	["ENDPOINTS_LOGIN_URL", "SESSION_LOGIN_PAGE_URL", "endpoints.login.url", "session.loginPage.url"],
	["SESSION_SECRET", "SESSION_STORE_SECRET", "session.secret", "session-store.secret"],
	["SESSION_NAME", "SESSION_STORE_NAME", "session.name", "session-store.name"],
	["SESSION_MAX_AGE", "SESSION_STORE_MAX_AGE", "session.maxAge", "session-store.maxAge"],
	["SESSION_SECURE", "SESSION_STORE_SECURE", "session.secure", "session-store.secure"],
	["SESSION_SAME_SITE", "SESSION_STORE_SAME_SITE", "session.sameSite", "session-store.sameSite"],
	["SESSION_DOMAIN", "SESSION_STORE_DOMAIN", "session.domain", "session-store.domain"],
	[
		"SESSION_STORAGE_TYPE",
		"SESSION_STORE_STORAGE_TYPE",
		"session.storage.type",
		"session-store.storage.type",
	],
	[
		"SESSION_STORAGE_REDIS_URL",
		"SESSION_STORE_STORAGE_REDIS_URL",
		"session.storage.redis.url",
		"session-store.storage.redis.url",
	],
	[
		"SESSION_STORAGE_REDIS_PASSWORD",
		"SESSION_STORE_STORAGE_REDIS_PASSWORD",
		"session.storage.redis.password",
		"session-store.storage.redis.password",
	],
] as const;

describe("the package's config/reference.conf", () => {
	it("is read at each module's name: session and session-store", () => {
		const modules = [sessionModule, sessionStoreModule];
		expect(modules.map((module) => module.name)).toEqual(["session", "session-store"]);
		expect(modules.map((module) => module.section?.at)).toEqual([undefined, undefined]);
		expect(modules.map((module) => module.section?.reference?.href)).toEqual([
			REFERENCE.href,
			REFERENCE.href,
		]);
		expect(moduleReferences(modules).map((reference) => reference.href)).toContain(REFERENCE.href);
	});

	it("is declared by each of them and holds only their sections, which their schemas parse without losing a path", () => {
		const read = (path: string, env: Readonly<Record<string, string>>): unknown =>
			parseFile(path, { env: { ...env } }).toObject();
		expect(
			packageReferenceProblems({
				reference: REFERENCE,
				modules: [sessionModule, sessionStoreModule],
				read,
			}),
		).toEqual([]);
	});

	it("ships the login page at /login, the login budget at 20 per 15 minutes, a __Host- cookie in redis, and no secret", () => {
		const shipped = defaults();
		expect(shipped).toMatchObject({
			session: {
				redirectAllowlist: [],
				csrf: { trustedOrigins: [], ttlSeconds: 7200 },
				loginPage: { url: "/login" },
				rateLimit: { login: { windowMs: 900_000, limit: 20 } },
			},
			"session-store": {
				name: "__Host-auth.session",
				maxAge: 3_600_000,
				secure: true,
				sameSite: "lax",
				domain: null,
				storage: { type: "redis", redis: { url: "redis://localhost:6379" } },
			},
		});
		expect(shipped["session-store"]).not.toHaveProperty("secret");
	});

	it.each(RENAMED)("binds %s's new name, %s, at %s's new path %s and in its capture", (from, to, _old, path) => {
		expect(bindings().filter((binding) => binding.startsWith(`${to} `))).toEqual([
			`${to} at ${path}`,
			`${to} at renamed-variables.${to}`,
		]);
		expect(bindings().filter((binding) => binding.startsWith(`${from} `))).toEqual([
			`${from} at renamed-variables.${from}`,
		]);
	});

	it("binds SESSION_CSRF_TTL_SECONDS at session.csrf.ttlSeconds alone: it was not renamed", () => {
		expect(
			bindings().filter((binding) => binding.startsWith("SESSION_CSRF_TTL_SECONDS ")),
		).toEqual(["SESSION_CSRF_TTL_SECONDS at session.csrf.ttlSeconds"]);
	});
});

describe("the paths the settings moved from, on the manifests", () => {
	it("session: the login page from endpoints.login.url, and the login's budget from rateLimit.login, which no variable binds", () => {
		expect(sessionModule.section?.relocatedFrom).toEqual({
			"endpoints.login.url": "loginPage.url",
			"rateLimit.login": { to: "rateLimit.login", environmentVariable: null },
		});
		expect(sessionModule.section?.renamedVariables).toEqual({
			ENDPOINTS_LOGIN_URL: "endpoints.login.url",
		});
	});

	it("session-store: each key of the cookie and its store from session, whichever form of the module", () => {
		const forms = [
			sessionStoreModule,
			sessionStoreModuleFor(makeValidAppConfig() as never),
			sessionStoreModuleFor(withStore(makeValidAppConfig(), { storage: { type: "redis" } }) as never),
		];
		for (const module of forms) {
			expect(module.section?.relocatedFrom).toEqual({
				"session.secret": "secret",
				"session.name": "name",
				"session.maxAge": "maxAge",
				"session.secure": "secure",
				"session.sameSite": "sameSite",
				"session.domain": "domain",
				"session.storage": { to: "storage", environmentVariable: null },
				"session.storage.type": "storage.type",
				"session.storage.redis.url": "storage.redis.url",
				"session.storage.redis.password": "storage.redis.password",
			});
			expect(module.section?.renamedVariables).toEqual(
				Object.fromEntries(
					RENAMED.filter(([from]) => from !== "ENDPOINTS_LOGIN_URL").map(([from, , old]) => [
						from,
						old,
					]),
				),
			);
		}
	});
});

describe("session-store's schema", () => {
	/** The fixture's session store section with `change` laid over it, parsed. */
	const parse = (change: Record<string, unknown>) =>
		sessionStoreConfigSchema.safeParse({
			...(makeValidAppConfig() as unknown as { "session-store": object })["session-store"],
			...change,
		});
	const messages = (result: ReturnType<typeof parse>): string =>
		result.success ? "" : result.error.issues.map((issue) => issue.message).join("\n");
	const paths = (result: ReturnType<typeof parse>): string[] =>
		result.success ? [] : result.error.issues.map((issue) => issue.path.join("."));

	it.each([
		["a one-character secret", "#"],
		["a short passphrase", "correct horse battery staple"],
		["a 32-character hex secret, 16 bytes decoded", "0123456789abcdef0123456789abcdef"],
	])("refuses %s, naming session-store.secret and SESSION_STORE_SECRET, never the value", (_what, secret) => {
		const result = parse({ secret });
		expect(paths(result)).toEqual(["secret"]);
		expect(messages(result)).toContain("session-store.secret");
		expect(messages(result)).toContain("SESSION_STORE_SECRET");
		expect(messages(result)).not.toContain(secret);
	});

	it("accepts a 64-character hex secret", () => {
		expect(parse({ secret: "0123456789abcdef".repeat(4) }).success).toBe(true);
	});

	it.each([
		["0, what an exported-but-empty SESSION_STORE_MAX_AGE coerces to", 0],
		["an empty string", ""],
		["a negative lifetime", -1],
		["a fractional lifetime", 1.5],
		["a lifetime above one year", MAX_DURATION_MS + 1],
	])("refuses a maxAge of %s", (_what, maxAge) => {
		expect(paths(parse({ maxAge }))).toContain("maxAge");
	});

	it.each([
		["one year", MAX_DURATION_MS],
		["one hour", 3_600_000],
		["the string a variable carries", "3600000"],
	])("accepts a maxAge of %s", (_what, maxAge) => {
		expect(parse({ maxAge }).success).toBe(true);
	});

	it.each([
		["true", true],
		["1", true],
		["false", false],
		["0", false],
		["", false],
	])("reads secure = %j, as SESSION_STORE_SECURE carries it, as %j", (secure, expected) => {
		const result = parse({ name: "auth.session", secure });
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.secure).toBe(expected);
	});

	it("refuses a secure it would have to guess at", () => {
		expect(paths(parse({ name: "auth.session", secure: "yes" }))).toContain("secure");
	});

	it('refuses sameSite = "none" with the secure = "false" a variable carries, naming SESSION_STORE_SECURE', () => {
		const result = parse({ name: "auth.session", sameSite: "none", secure: "false" });
		expect(paths(result)).toEqual(["secure"]);
		expect(messages(result)).toContain("SESSION_STORE_SECURE=true");
	});

	it.each(["redis", "memory", "memcached"])(
		"accepts storage.type = %j, which the store factory decides on, and keeps every type's block",
		(type) => {
			const result = parse({
				storage: {
					type,
					redis: { url: "redis://localhost:6379" },
					memcached: { servers: ["mc1.example.com:11211"] },
				},
			});
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.storage).toEqual({
					type,
					redis: { url: "redis://localhost:6379" },
					memcached: { servers: ["mc1.example.com:11211"] },
				});
			}
		},
	);

	it("accepts a storage with no redis block for a type other than redis", () => {
		expect(parse({ storage: { type: "memory" } }).success).toBe(true);
	});

	it("refuses a key it does not declare, naming it", () => {
		expect(messages(parse({ secrett: "x" }))).toContain('"secrett"');
		expect(
			paths(parse({ storage: { type: "redis", redis: { url: "redis://x", passwrd: "p" } } })),
		).toEqual(["storage.redis"]);
	});
});

describe("session's schema", () => {
	const parse = (section: Record<string, unknown>) => sessionSectionSchema.safeParse(section);
	const paths = (result: ReturnType<typeof parse>): string[] =>
		result.success ? [] : result.error.issues.map((issue) => issue.path.join("."));

	it("reads csrf.ttlSeconds from the string a variable carries", () => {
		const result = parse({ csrf: { trustedOrigins: [], ttlSeconds: "900" } });
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.csrf?.ttlSeconds).toBe(900);
	});

	it.each([0, -1, "", 7200.5, 86_401])("refuses a csrf.ttlSeconds of %j", (ttlSeconds) => {
		expect(paths(parse({ csrf: { trustedOrigins: [], ttlSeconds } }))).toEqual([
			"csrf.ttlSeconds",
		]);
	});

	it("accepts a csrf.ttlSeconds at the 86400 ceiling", () => {
		expect(parse({ csrf: { trustedOrigins: [], ttlSeconds: 86_400 } }).success).toBe(true);
	});

	it.each([
		["a zero window, which turns the guard off", { windowMs: 0, limit: 20 }, "rateLimit.login.windowMs"],
		["a window above the ceiling", { windowMs: MAX_DURATION_MS + 1, limit: 20 }, "rateLimit.login.windowMs"],
		["a zero limit", { windowMs: 900_000, limit: 0 }, "rateLimit.login.limit"],
	])("refuses rateLimit.login with %s", (_what, login, path) => {
		expect(paths(parse({ rateLimit: { login } }))).toEqual([path]);
	});

	it("accepts the shipped 15-minute, 20-attempt login budget, and its variables' strings", () => {
		expect(parse({ rateLimit: { login: { windowMs: 900_000, limit: 20 } } }).success).toBe(true);
		expect(parse({ rateLimit: { login: { windowMs: "900000", limit: "20" } } }).success).toBe(true);
	});

	it("refuses an empty loginPage.url", () => {
		expect(paths(parse({ loginPage: { url: "" } }))).toEqual(["loginPage.url"]);
	});

	it.each([
		["a path", "/login?redirect_to=https://x"],
		["an absolute URL", "https://login.example/signin?tenant=x&redirect_to=https%3A%2F%2Fx"],
		["a name written percent-encoded", "/login?redirect%5Fto=x"],
		["a name with no value", "/login?tenant=x&redirect_to"],
		// The rule reads the query as the redirect writes it -- the text before
		// any `#`, after the first `?` -- so a URL `URL` cannot parse is held to
		// it too: the redirect would append a second one all the same.
		["a URL that does not parse", "http://[::1/login?redirect_to=x"],
		["a URL that does not parse, with a fragment", "http://[::1/login?tenant=x&redirect_to=y#z"],
	])("refuses a loginPage.url that is %s whose own query carries redirect_to, naming the key", (_what, url) => {
		const result = parse({ loginPage: { url } });
		expect(paths(result)).toEqual(["loginPage.url"]);
		const message = result.error?.issues[0]?.message;
		expect(message).toContain("session.loginPage.url");
		expect(message).toContain('"redirect_to"');
		expect(message).toContain("the provider adds");
	});

	it.each([
		["a query of its own", "/login?tenant=x"],
		["an absolute URL with a query", "https://login.example/signin?tenant=x"],
		["redirect_to inside the fragment alone", "/login#redirect_to=https://x"],
		["a query, and redirect_to inside the fragment", "/login?tenant=x#redirect_to=y"],
		["a name that differs in case", "/login?Redirect_To=x"],
		["a longer name", "/login?redirect_to_after=x"],
		["a URL that does not parse, without redirect_to", "http://[::1/login?tenant=x"],
		["a `?` inside the fragment alone", "/login#a?redirect_to=x"],
	])("accepts a loginPage.url with %s", (_what, url) => {
		expect(parse({ loginPage: { url } }).success).toBe(true);
	});

	it.each([
		[{ loginPage: { url: "/login", urll: "/typo" } }, "urll"],
		[{ rateLimit: { login: { windowMs: 1, limit: 1 }, failMode: "open" } }, "failMode"],
		[{ secret: "moved" }, "secret"],
		// Milliseconds, the unit the login's window has always been written in.
		[{ rateLimit: { login: { windowSeconds: 900, limit: 20 } } }, "windowSeconds"],
	])("refuses %j, naming the key it does not declare", (section, key) => {
		const result = parse(section);
		expect(result.success).toBe(false);
		expect(result.error?.issues.map((issue) => issue.message).join("\n")).toContain(`"${key}"`);
	});
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

const providing = <T,>(name: string, slot: string, value: T) =>
	defineModule({ name, provides: { [slot]: () => value } as never });

/** What the session module requires besides the session store's slots, so a refusal names the configuration. */
const STORES = [
	providing("test:user-repository", "userRepository", {
		authenticate: async () => null,
		authenticateByToken: async () => null,
	} as unknown as UserRepository),
	providing("test:user-session-store", "userSessionStore", {
		kind: "memory",
		async create() {},
		async get() {
			return null;
		},
		async delete() {},
	} as unknown as UserSessionStore),
	providing("test:federation-token-store", "federationTokenStore", {
		kind: "memory",
		async attach() {},
		async get() {
			return null;
		},
		async update() {},
		async removeBySid() {},
		async delete() {},
	} as unknown as FederationTokenStore),
	providing("test:session-federation-index", "sessionFederationIndex", {
		kind: "memory",
		async addFederation() {},
		async listFederations() {
			return [];
		},
		async removeFederation() {},
		async removeBySid() {},
	} as unknown as SessionFederationIndex),
];

describe("boot, over a configuration that captures the modules' renamed variables", () => {
	/** Boots both modules over the fixture's configuration with `change` laid over it, and what the resolution captured. */
	const boot = (
		change: (config: Record<string, unknown>) => Record<string, unknown>,
		captured: Record<string, string> = {},
	) => {
		const config = withSessionCaptures(
			change(makeValidAppConfig() as unknown as Record<string, unknown>),
		);
		return createApp({
			modules: [sessionModule, sessionStoreModule, ...STORES],
			bootstrapComponents: {
				config: {
					...config,
					"renamed-variables": { ...(config["renamed-variables"] as object), ...captured },
				},
				pathResolver: (s: string) => s,
			} as never,
		});
	};

	/** What boot refused the composition with. */
	async function refusal(
		change: (config: Record<string, unknown>) => Record<string, unknown>,
		captured: Record<string, string> = {},
	): Promise<BootError> {
		try {
			const handle = await boot(change, captured);
			await handle.dispose();
		} catch (err) {
			expect(err).toBeInstanceOf(BootError);
			return err as BootError;
		}
		return expect.fail("boot should have been refused");
	}

	it("boots the fixture's configuration", async () => {
		const handle = await boot((config) => config);
		await handle.dispose();
	});

	it.each([
		[
			{ secret: "a".repeat(64) },
			"session-store",
			"session.secret",
			"session-store.secret",
			"SESSION_STORE_SECRET",
		],
		[
			{ sameSite: "strict" },
			"session-store",
			"session.sameSite",
			"session-store.sameSite",
			"SESSION_STORE_SAME_SITE",
		],
		[
			{ storage: { type: "redis", redis: { url: "redis://cache:6379" } } },
			"session-store",
			"session.storage.redis.url",
			"session-store.storage.redis.url",
			"SESSION_STORE_STORAGE_REDIS_URL",
		],
	])("refuses session %j, naming the key's path under session-store and its variable", async (keys, module, from, to, variable) => {
		const err = await refusal((config) => withSession(config, keys));

		expect(err.reason).toBe("config-path-relocated");
		expect((err.details as unknown as { relocated: unknown[] }).relocated).toContainEqual({
			module,
			from,
			to,
			environmentVariable: variable,
		});
	});

	it("refuses endpoints.login.url, naming session.loginPage.url and SESSION_LOGIN_PAGE_URL", async () => {
		const err = await refusal((config) => ({ ...config, endpoints: { login: { url: "/login" } } }));

		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "session",
					from: "endpoints.login.url",
					to: "session.loginPage.url",
					environmentVariable: "SESSION_LOGIN_PAGE_URL",
				},
			],
		});
	});

	it("refuses rateLimit.login, naming session.rateLimit.login and no variable", async () => {
		const err = await refusal((config) => ({
			...config,
			rateLimit: { login: { windowMs: 900_000, limit: 20 } },
		}));

		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "session",
					from: "rateLimit.login.windowMs",
					to: "session.rateLimit.login.windowMs",
				},
				{ module: "session", from: "rateLimit.login.limit", to: "session.rateLimit.login.limit" },
			],
		});
	});

	it.each(RENAMED)("refuses %s set alone, naming %s", async (from, to, _old, path) => {
		const err = await refusal((config) => config, { [from]: "value-set-alone" });

		expect(err.details).toMatchObject({
			reason: "environment-variable-renamed",
			renamed: [{ from, to, path, state: "unset" }],
		});
		expect(err.message).not.toContain("value-set-alone");
	});

	it("refuses SESSION_SECRET and SESSION_STORE_SECRET set to different values, printing neither", async () => {
		const err = await refusal((config) => config, {
			SESSION_SECRET: "old-secret-value",
			SESSION_STORE_SECRET: "new-secret-value",
		});

		expect(err.details).toMatchObject({
			reason: "environment-variable-renamed",
			renamed: [
				{
					module: "session-store",
					from: "SESSION_SECRET",
					to: "SESSION_STORE_SECRET",
					path: "session-store.secret",
					state: "different",
				},
			],
		});
		expect(err.message).not.toContain("old-secret-value");
		expect(err.message).not.toContain("new-secret-value");
	});

	it("boots with SESSION_SECRET and SESSION_STORE_SECRET set to the same value", async () => {
		const secret = (makeValidAppConfig() as unknown as { "session-store": { secret: string } })[
			"session-store"
		].secret;
		const handle = await boot((config) => config, {
			SESSION_SECRET: secret,
			SESSION_STORE_SECRET: secret,
		});
		await handle.dispose();
	});

	it("refuses a session-store with no secret, naming SESSION_STORE_SECRET", async () => {
		const err = await refusal((config) => {
			const { secret: _secret, ...store } = config["session-store"] as Record<string, unknown>;
			return { ...config, "session-store": store };
		});

		expect(err.message).toContain("session-store.secret is not set");
		expect(err.message).toContain("SESSION_STORE_SECRET");
	});

	it.each([
		["a path", "/login?redirect_to=https://x"],
		["an absolute URL", "https://login.example/signin?redirect_to=https%3A%2F%2Fx"],
	])("refuses a session.loginPage.url that is %s carrying redirect_to, naming the key", async (_what, url) => {
		const err = await refusal((config) => withSession(config, { loginPage: { url } }));

		expect(err.reason).toBe("config-validation-failed");
		expect((err.details as unknown as { issues: unknown[] }).issues).toContainEqual(
			expect.objectContaining({
				path: ["session", "loginPage", "url"],
				message: expect.stringMatching(/"redirect_to".*the provider adds/),
			}),
		);
	});

	it("boots a session.loginPage.url with a query of its own", async () => {
		const handle = await boot((config) =>
			withSession(config, { loginPage: { url: "/login?tenant=x" } }),
		);
		await handle.dispose();
	});

	it.each([
		["session", { redirectAllowlist: [], loginPag: { url: "/login" } }, "loginPag"],
		["session-store", { storag: { type: "memory" } }, "storag"],
	] as const)("refuses a key %s does not declare, naming it", async (section, keys, key) => {
		const err = await refusal((config) =>
			section === "session" ? withSession(config, keys) : withStore(config, keys),
		);

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain(`"${key}"`);
	});
});
