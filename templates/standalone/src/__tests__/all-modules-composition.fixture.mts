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
 * The composition `all-modules-composition*.test.mts` boot: every module this
 * template can turn on, switched on together from the shipped HOCON, and
 * mounted the way `app.mts` mounts it.
 *
 * What is real: the configuration (`config/*.conf` over core's
 * `reference.conf`, resolved with the environment a deployment would export),
 * `buildModules`, core's `createApp`, every module and store it selects, the
 * key store, the audit sink, `helmet` and the terminal error handler.
 *
 * What is substituted, and why:
 *
 * - The client and user repositories — `repositoriesModule` reads YAML files
 *   off disk; the in-memory repositories carry the registrations the flows
 *   need. `buildModules` offers this override for the purpose.
 * - The refresh-token family store under `deployment.mode = "single"` — the
 *   shipped composition always puts it on Redis; the memory store keeps the
 *   single-replica boot free of sockets. `buildModules` offers this override.
 * - The upstream identity providers — core's fake OpenID Provider behind a
 *   `fetch`, handed to the Google and OIDC adapters through the `fetch` option
 *   each adapter takes for exactly this. The config bridges' values are read
 *   through the template's own bridge (`googleFederationConfigModule`) and the
 *   OIDC package's reader, and only `fetch` is added.
 * - Configuration with no environment form (a map of grant connections, a key
 *   ring, a landing URL): laid over the resolved config, as an operator would
 *   write it in `application.conf`.
 *
 * `tools/composition` in the monorepo imports this file and boots the same
 * composition with the workspace's other modules added (`ComposeOptions`'s
 * `referenceConfs`, `extraModules`, `extraOverrides`, `extraClients` and
 * `extraUsers`), so the two suites share one fixture rather than two copies
 * that drift.
 */

import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import {
	type AppConfig,
	AppConfigSchema,
	ClientEntrySchema,
	createApp,
	defineModule,
	InMemoryClientRepository,
	InMemoryUserRepository,
	type Logger,
	type Module,
	memoryRefreshTokenFamilyStoreModule,
} from "@o3co/auth-provider-core";
import { createFakeIdp, type FakeIdp } from "@o3co/auth-provider-core/testing";
import { readOidcFederationConfigs } from "@o3co/auth-provider-federation-oidc";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import express from "express";
import helmet from "helmet";
import request from "supertest";
import { expect } from "vitest";
import { buildModules } from "#/buildModules.mjs";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "#/configPath.mjs";
import { googleFederationConfigModule } from "#/modules.mjs";
import { createTerminalErrorHandler } from "#/terminalError.mjs";

export const ISSUER = "https://auth.test";
const OIDC_ISSUER = "https://idp.test";
/** Where a federated login lands the browser when the start carried no `redirect_to`. */
export const FEDERATION_LANDING = "https://app.test/home";

const signingKey = generateKeyPairSync("ed25519", {
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
/** 32 bytes, base64 — the shape every at-rest encryption key here takes. */
const ENCRYPTION_KEY = Buffer.alloc(32, 7).toString("base64");

/**
 * One replica, every store in memory, every feature the template can switch
 * on switched on: the four token grants, the consent step with Client ID
 * Metadata Documents, federation grants, the Google federation and the
 * shipped generic OIDC one.
 */
export const SINGLE_ENV: Readonly<Record<string, string>> = {
	OAUTH_JWT_ISSUER: ISSUER,
	// The shipped default algorithm (EdDSA), with the key pair inline.
	OAUTH_JWT_PRIVATE_KEY: signingKey.privateKey,
	OAUTH_JWT_PUBLIC_KEY: signingKey.publicKey,
	SESSION_SECRET: "all-modules-composition-session.at-least-32-bytes.ok",
	SESSION_SECURE: "false",
	SESSION_NAME: "auth.session",
	DEPLOYMENT_MODE: "single",
	SESSION_STORAGE_TYPE: "memory",
	USER_SESSION_STORES_ADAPTER: "memory",
	RATE_LIMITER_ADAPTER: "memory",
	OAUTH_CODE_ADAPTER: "memory",
	ACCESS_TOKEN_DENYLIST_ADAPTER: "memory",
	REPLAY_SEEN_SET_ADAPTER: "memory",
	FEDERATION_TOKEN_STORE_TYPE: "memory",
	CONSENT_STORE_ADAPTER: "memory",
	FEDERATION_GRANT_STORE_ADAPTER: "memory",
	FEDERATION_GRANT_INTENT_STORE_ADAPTER: "memory",
	// The user repository is replaced (see the header); `yaml` keeps the
	// shipped `http` adapter's URL requirements out of config validation.
	CLIENT_USER_TYPE: "yaml",
	OAUTH_GRANTS_SESSION_ENABLED: "true",
	OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED: "true",
	OAUTH_GRANTS_REFRESH_TOKEN_ENABLED: "true",
	OAUTH_GRANTS_CLIENT_CREDENTIALS_ENABLED: "true",
	OAUTH_CIMD_ENABLED: "true",
	FEDERATION_GRANTS_ENABLED: "true",
	FEDERATION_GRANTS_CONSENT_URL: "/consent/grants",
	// The in-memory user repository covers no registration; `required` is a
	// Store's statement that it does (see the federation-grants README).
	FEDERATION_GRANTS_IDENTITY_LOOKUP: "unsupported",
	FEDERATIONS_GOOGLE_ENABLED: "true",
	FEDERATIONS_GOOGLE_CLIENT_ID: "google-client",
	FEDERATIONS_GOOGLE_CLIENT_SECRET: "google-secret",
	FEDERATIONS_OIDC_ENABLED: "true",
	FEDERATIONS_OIDC_ISSUER: OIDC_ISSUER,
	FEDERATIONS_OIDC_CLIENT_ID: "oidc-client",
	FEDERATIONS_OIDC_CLIENT_SECRET: "oidc-secret",
};

/**
 * The same deployment on more than one replica: every shared store on Redis,
 * express-session's own included (the umbrella E2E's shape).
 */
export const MULTI_ENV: Readonly<Record<string, string>> = {
	...SINGLE_ENV,
	DEPLOYMENT_MODE: "multi",
	SESSION_STORAGE_TYPE: "redis",
	SESSION_STORAGE_REDIS_URL: "redis://redis.test:6379",
	REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: "redis://redis.test:6379",
	USER_SESSION_STORES_ADAPTER: "redis",
	RATE_LIMITER_ADAPTER: "redis",
	OAUTH_CODE_ADAPTER: "redis",
	ACCESS_TOKEN_DENYLIST_ADAPTER: "redis",
	REPLAY_SEEN_SET_ADAPTER: "redis",
	FEDERATION_TOKEN_STORE_TYPE: "redis",
	REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY: ENCRYPTION_KEY,
	CONSENT_STORE_ADAPTER: "redis",
	FEDERATION_GRANT_STORE_ADAPTER: "redis",
	FEDERATION_GRANT_INTENT_STORE_ADAPTER: "redis",
};

/** The grant connection the federation-grant flows use, on the shipped `oidc` federation. */
export const CONNECTION = "calendar";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

/**
 * The shipped HOCON under `env`, with what has no environment form laid over
 * it: the federations' landing page, the grant key ring and one grant
 * connection. `referenceConfs` — other packages' `reference.conf` files — are
 * layered between `application.conf` and core's, as a deployment layers them.
 */
export function resolveConfig(
	env: Readonly<Record<string, string>>,
	referenceConfs: readonly string[] = [],
): AppConfig {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	const read = (path: string) => parseFile(path, { env: { ...env } });
	const layered = [
		applicationConfPath,
		...referenceConfs,
		resolveLibraryReferenceConfPath(),
	].reduce((config, path) => config.withFallback(read(path)), read(envConfPath));
	const resolved = validate(layered, AppConfigSchema);
	const federations = resolved.federations as Record<string, Record<string, unknown>>;
	return {
		...resolved,
		federations: {
			...federations,
			google: { ...federations.google, clientUrl: FEDERATION_LANDING },
			oidc: { ...federations.oidc, clientUrl: FEDERATION_LANDING },
		},
		federationGrants: {
			...resolved.federationGrants,
			encryptionKeys: [{ id: "k-test", key: ENCRYPTION_KEY }],
			connections: {
				[CONNECTION]: {
					federation: "oidc",
					scopes: ["openid", "offline_access", "calendar.read"],
					boundary: "production",
					maxAccessTokenLifetime: 3600,
					callbackURL: `${ISSUER}/session/federation-grants/callback/${CONNECTION}`,
				},
			},
		},
	} as unknown as AppConfig;
}

// ---------------------------------------------------------------------------
// Registrations
// ---------------------------------------------------------------------------

export const WEB = { id: "web", secret: "web-secret", redirectUri: "https://rp.test/cb" } as const;
export const M2M = { id: "m2m", secret: "m2m-secret" } as const;
export const WORKER = {
	id: "worker",
	secret: "worker-secret",
	redirectUri: "https://worker.test/connected",
} as const;
/** Not first-party: `/authorize` sends its user through the consent step. */
export const THIRD = {
	id: "third",
	secret: "third-secret",
	redirectUri: "https://third.test/cb",
} as const;

export const ALICE = { username: "alice", password: "correct-horse-battery", sub: "u-alice" };
/** The subjects the fake IdPs sign in, as the Store has them linked. */
const OIDC_SUB = "idp-sub";
const GOOGLE_SUB = "google-sub";

type ClientEntry = ReturnType<typeof ClientEntrySchema.parse>;

const clientEntries = (
	extra: Readonly<Record<string, Record<string, unknown>>> = {},
): Map<string, ClientEntry> =>
	new Map<string, ClientEntry>([
		...Object.entries(extra).map(
			([id, entry]) => [id, ClientEntrySchema.parse(entry)] as [string, ClientEntry],
		),
		[
			WEB.id,
			ClientEntrySchema.parse({
				tokenEndpointAuthMethod: "client_secret_basic",
				clientSecret: WEB.secret,
				allowedRedirectUris: [WEB.redirectUri],
				allowedScopes: ["openid", "profile", "email", "offline_access"],
				allowedGrantTypes: ["authorization_code", "refresh_token", "session"],
				firstParty: true,
			}),
		],
		[
			M2M.id,
			ClientEntrySchema.parse({
				tokenEndpointAuthMethod: "client_secret_basic",
				clientSecret: M2M.secret,
				allowedScopes: ["api.read"],
				allowedGrantTypes: ["client_credentials"],
			}),
		],
		[
			WORKER.id,
			ClientEntrySchema.parse({
				tokenEndpointAuthMethod: "client_secret_basic",
				clientSecret: WORKER.secret,
				allowedScopes: ["openid"],
				allowedGrantTypes: [],
				allowedFederationGrantConnections: [CONNECTION],
				federationGrantRedirectUris: [WORKER.redirectUri],
			}),
		],
		[
			THIRD.id,
			ClientEntrySchema.parse({
				tokenEndpointAuthMethod: "client_secret_basic",
				clientSecret: THIRD.secret,
				allowedRedirectUris: [THIRD.redirectUri],
				allowedScopes: ["openid"],
				allowedGrantTypes: ["authorization_code"],
			}),
		],
	]);

const testRepositoriesModule = (
	extraClients: Readonly<Record<string, Record<string, unknown>>> = {},
	extraUsers: Readonly<Record<string, Record<string, unknown>>> = {},
): Module =>
	defineModule({
		name: "test:repositories",
		provides: {
			clientRepository: () => new InMemoryClientRepository(clientEntries(extraClients)),
			userRepository: () =>
				new InMemoryUserRepository(
					new Map([
						[
							ALICE.username,
							{
								id: ALICE.sub,
								password: ALICE.password,
								email: "alice@example.com",
								token: `oidc:${OIDC_SUB}`,
							},
						],
						["bob", { id: "u-bob", password: "bob-password-long", token: `google:${GOOGLE_SUB}` }],
						...Object.entries(extraUsers),
					]) as ConstructorParameters<typeof InMemoryUserRepository>[0],
				),
		},
	});

// ---------------------------------------------------------------------------
// Upstream identity providers
// ---------------------------------------------------------------------------

export interface Upstreams {
	readonly oidc: FakeIdp;
	readonly google: FakeIdp;
}

let upstreams: Promise<Upstreams> | undefined;

/**
 * The two fake upstreams, made once per test file: each signs under an RSA key
 * it generates, and a login's state lives in the authorization it recorded,
 * so boots can share them.
 */
export function sharedUpstreams(): Promise<Upstreams> {
	upstreams ??= createUpstreams();
	return upstreams;
}

async function createUpstreams(): Promise<Upstreams> {
	return {
		oidc: await createFakeIdp({
			issuer: OIDC_ISSUER,
			discovery: true,
			clientId: SINGLE_ENV.FEDERATIONS_OIDC_CLIENT_ID,
			sub: OIDC_SUB,
		}),
		// Google's endpoints are fixed in the adapter, not discovered.
		google: await createFakeIdp({
			issuer: "https://accounts.google.com",
			authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
			tokenEndpoint: "https://oauth2.googleapis.com/token",
			jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
			userinfoEndpoint: "https://www.googleapis.com/oauth2/v3/userinfo",
			clientId: SINGLE_ENV.FEDERATIONS_GOOGLE_CLIENT_ID,
			sub: GOOGLE_SUB,
		}),
	};
}

/**
 * The two federation config slots, read the way the template's bridges read
 * them, with each adapter's `fetch` pointed at its fake upstream. Only for the
 * federations the config enables.
 */
async function federationOverrides(
	config: AppConfig,
	upstreams: Upstreams,
): Promise<Record<string, unknown>> {
	const overrides: Record<string, unknown> = {};
	const oidc = readOidcFederationConfigs(config.federations);
	if (Object.keys(oidc).length > 0) {
		overrides.oidcFederationConfigs = Object.fromEntries(
			Object.entries(oidc).map(([name, entry]) => [
				name,
				{ ...entry, fetch: upstreams.oidc.fetch },
			]),
		);
	}
	const federations = config.federations as Record<string, { enabled?: unknown }> | undefined;
	if (federations?.google?.enabled === true) {
		// Read through a record, not the typed slot: a program that loads this
		// file without the Google package's ComponentMap augmentation
		// (`tools/composition` does) has no `googleFederationConfig` key to name.
		const provides = googleFederationConfigModule.provides as Record<string, unknown> | undefined;
		const bridge = provides?.googleFederationConfig as (deps: {
			config: AppConfig;
		}) => Record<string, unknown>;
		overrides.googleFederationConfig = { ...bridge({ config }), fetch: upstreams.google.fetch };
	}
	return overrides;
}

// ---------------------------------------------------------------------------
// Logger spy
// ---------------------------------------------------------------------------

export interface LogLine {
	readonly level: "trace" | "debug" | "info" | "warn" | "error" | "fatal";
	readonly args: readonly unknown[];
}

export interface RecordingLogger extends Logger {
	readonly lines: LogLine[];
}

/** A `Logger` that records every call, its children's included, in one list. */
export function createRecordingLogger(): RecordingLogger {
	const lines: LogLine[] = [];
	const make = (bindings: Record<string, unknown>): Logger => {
		const at =
			(level: LogLine["level"]) =>
			(...args: unknown[]): void => {
				const [first, ...rest] = args;
				lines.push({
					level,
					args:
						typeof first === "object" && first !== null && Object.keys(bindings).length > 0
							? [{ ...bindings, ...first }, ...rest]
							: args,
				});
			};
		return {
			trace: at("trace"),
			debug: at("debug"),
			info: at("info"),
			warn: at("warn"),
			error: at("error"),
			fatal: at("fatal"),
			child: (more) => make({ ...bindings, ...more }),
		} as Logger;
	};
	return Object.assign(make({}), { lines }) as RecordingLogger;
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

/** A switch an outage wrapper reads on every call. */
export interface Outage {
	down: boolean;
}

/** What a store adapter's client throws when its connection is refused. */
const connectionRefused = (): Error =>
	Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:6379"), { code: "ECONNREFUSED" });

/** Every method of `target` rejects while `outage.down`, and is the real one otherwise. */
function failWhileDown<T extends object>(target: T, outage: Outage): T {
	return new Proxy(target, {
		get(object, property) {
			const value = Reflect.get(object, property, object);
			if (typeof value !== "function") return value;
			return (...args: unknown[]): unknown =>
				outage.down
					? Promise.reject(connectionRefused())
					: (value as (...a: unknown[]) => unknown).apply(object, args);
		},
	});
}

/**
 * `modules` with the provider of `slot` wrapped by {@link failWhileDown}: the
 * real module, named and declared as it is, handing out the real store.
 */
function withOutage(modules: readonly Module[], slot: string, outage: Outage): Module[] {
	let found = false;
	const wrapped = modules.map((module) => {
		const provides = module.provides as
			| Record<string, (deps: unknown) => unknown | Promise<unknown>>
			| undefined;
		const provider = provides?.[slot];
		if (provider === undefined) return module;
		found = true;
		return {
			...module,
			provides: {
				...provides,
				[slot]: async (deps: unknown) => failWhileDown((await provider(deps)) as object, outage),
			},
		} as Module;
	});
	if (!found) throw new Error(`no module in the composition provides ${slot}`);
	return wrapped;
}

/** The order `buildModules` lists the modules in. */
export const AS_LISTED = "as listed";
/**
 * Every module after the first in reverse. The first, express-session's
 * middleware, is placed by list position alone (`buildModules` says so), so
 * it stays first; everything else changes place.
 */
export const REVERSED = "reversed";
export type ModuleOrder = typeof AS_LISTED | typeof REVERSED;

export interface ComposeOptions {
	readonly env?: Readonly<Record<string, string>>;
	/** Other packages' `reference.conf` files, layered above core's (see `resolveConfig`). */
	readonly referenceConfs?: readonly string[];
	/** Modules added after the template's own, before the order and the outage apply. */
	readonly extraModules?: (config: AppConfig) => readonly Module[];
	/** Components laid over the boot's, beside the federation config slots. */
	readonly extraOverrides?: (config: AppConfig) => Record<string, unknown>;
	/** Client registrations beside the fixture's own, as `ClientEntrySchema` input. */
	readonly extraClients?: Readonly<Record<string, Record<string, unknown>>>;
	/** Users beside the fixture's own, keyed by username. */
	readonly extraUsers?: Readonly<Record<string, Record<string, unknown>>>;
	/** Adjust the resolved config before anything reads it. */
	readonly config?: (config: AppConfig) => AppConfig;
	readonly order?: ModuleOrder;
	readonly outage?: { readonly slot: string; readonly outage: Outage };
	/** Keep the shipped Redis refresh-token family store (the `multi` boot). */
	readonly shippedRefreshTokenFamilyStore?: boolean;
}

/** The module list the template boots for `config`, as `app.mts` builds it. */
export function composedModules(config: AppConfig, options: ComposeOptions = {}): Module[] {
	let modules = [
		...buildModules(config, {
			environment: "production",
			repositoriesModule: testRepositoriesModule(options.extraClients, options.extraUsers),
			...(options.shippedRefreshTokenFamilyStore
				? {}
				: { refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule] }),
		}),
		...(options.extraModules?.(config) ?? []),
	];
	if (options.outage) modules = withOutage(modules, options.outage.slot, options.outage.outage);
	if (options.order === REVERSED) modules = [modules[0], ...modules.slice(1).reverse()];
	return modules;
}

export interface Composition {
	readonly app: express.Express;
	readonly handle: Awaited<ReturnType<typeof createApp>>;
	readonly config: AppConfig;
	readonly modules: readonly Module[];
	readonly logger: RecordingLogger;
	readonly upstreams: Upstreams;
}

/**
 * Boots the composition and mounts it as `app.mts` does: `helmet`, the
 * composed router, and the terminal error handler last, all on one logger
 * that is also the boot's `logger` component.
 */
export async function compose(options: ComposeOptions = {}): Promise<Composition> {
	const base = resolveConfig(options.env ?? SINGLE_ENV, options.referenceConfs);
	const config = options.config ? options.config(base) : base;
	const fakes = await sharedUpstreams();
	const modules = composedModules(config, options);
	const logger = createRecordingLogger();
	const handle = await createApp({
		modules,
		bootstrapComponents: { config, pathResolver: (s) => s, logger },
		overrideComponents: {
			...(await federationOverrides(config, fakes)),
			...options.extraOverrides?.(config),
		} as never,
	});
	const app = express();
	app.set("trust proxy", config.http.trustProxy);
	app.use(
		helmet({
			contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
		}),
	);
	app.use(handle.router);
	app.use(createTerminalErrorHandler(logger));
	return { app, handle, config, modules, logger, upstreams: fakes };
}

// ---------------------------------------------------------------------------
// Flows
// ---------------------------------------------------------------------------

export const basic = (client: { id: string; secret: string }): string =>
	`Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`;

const cookiesOf = (res: request.Response): string[] =>
	(res.headers["set-cookie"] as unknown as string[] | undefined) ?? [];

/** The browser half: a CSRF pair, then the password login. */
export async function login(
	app: express.Express,
): Promise<{ readonly res: request.Response; readonly cookies: string[] }> {
	const csrf = await request(app).get("/session/csrf");
	const res = await request(app)
		.post("/session/login")
		.set("Cookie", cookiesOf(csrf))
		.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
		.type("form")
		.send({ username: ALICE.username, password: ALICE.password });
	return { res, cookies: res.status === 200 ? cookiesOf(res) : cookiesOf(csrf) };
}

export const PKCE = (() => {
	const verifier = randomBytes(32).toString("base64url");
	return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
})();

export function authorize(
	app: express.Express,
	cookies: readonly string[],
	client: { id: string; redirectUri: string } = WEB,
): request.Test {
	return request(app)
		.get("/oauth/authorize")
		.set("Cookie", [...cookies])
		.query({
			response_type: "code",
			client_id: client.id,
			redirect_uri: client.redirectUri,
			scope: client === WEB ? "openid profile offline_access" : "openid",
			state: "af0ifjsldkj",
			nonce: "n-0S6_WzA2Mj",
			code_challenge: PKCE.challenge,
			code_challenge_method: "S256",
		});
}

export const codeFrom = (res: request.Response): string => {
	const code = new URL(res.headers.location as string).searchParams.get("code");
	if (code === null) throw new Error(`no code in ${res.status} ${res.headers.location}`);
	return code;
};

export function redeem(app: express.Express, code: string): request.Test {
	return request(app).post("/oauth/token").set("Authorization", basic(WEB)).type("form").send({
		grant_type: "authorization_code",
		code,
		redirect_uri: WEB.redirectUri,
		code_verifier: PKCE.verifier,
	});
}

/** Log in, authorize with PKCE, redeem: the web client's tokens. */
export async function webTokens(app: express.Express): Promise<Record<string, string>> {
	const { cookies } = await login(app);
	const res = await redeem(app, codeFrom(await authorize(app, cookies)));
	if (res.status !== 200) throw new Error(`code exchange answered ${res.status}`);
	return res.body as Record<string, string>;
}

/**
 * Start a federated login and play the upstream. What comes back sends the
 * callback when called — a function, because a supertest request is a
 * thenable, and returning one from an async function would send it.
 */
export async function federatedCallback(
	app: express.Express,
	name: "oidc" | "google",
	upstream: FakeIdp,
): Promise<() => request.Test> {
	const start = await request(app).get(`/session/oauth/federation/${name}`);
	if (start.status !== 302) throw new Error(`federation start answered ${start.status}`);
	const answer = upstream.authorize(start.headers.location as string);
	return () =>
		request(app)
			.get(`/session/oauth/federation/${name}/callback`)
			.set("Cookie", cookiesOf(start))
			.query({ code: answer.code, state: answer.state ?? "", iss: answer.iss });
}

export function lodgeGrant(app: express.Express): request.Test {
	return request(app).post("/oauth/federation-grants").set("Authorization", basic(WORKER)).send({
		connection: CONNECTION,
		sub: ALICE.sub,
		redirect_uri: WORKER.redirectUri,
		state: "worker-state",
	});
}

export { cookiesOf };

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

export const DISCOVERY_PATHS = [
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
] as const;

/**
 * What RFC 8414 §2 and OpenID Connect Discovery §3 require of the document
 * this composition serves, and what each advertised URL must be: https, on
 * the issuer's origin.
 */
export function expectValidMetadata(doc: Record<string, unknown>): void {
	expect(doc.issuer).toBe(ISSUER);
	for (const field of [
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	]) {
		expect(doc[field], field).toBeDefined();
	}
	for (const [field, value] of Object.entries(doc)) {
		if (field.endsWith("_endpoint") || field === "jwks_uri") {
			const url = new URL(value as string);
			expect(url.origin, field).toBe(ISSUER);
			expect(url.search + url.hash, field).toBe("");
		}
		if (field.endsWith("_supported") && Array.isArray(value)) {
			expect(value.length, field).toBeGreaterThan(0);
			for (const entry of value) expect(typeof entry, field).toBe("string");
			expect(new Set(value).size, `${field} repeats a value`).toBe(value.length);
		}
	}
	expect(doc.response_types_supported).toEqual(["code"]);
	expect(doc.code_challenge_methods_supported).toEqual(["S256"]);
}
