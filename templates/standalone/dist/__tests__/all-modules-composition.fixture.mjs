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
import { readFileSync } from "node:fs";
import http from "node:http";
import { fileURLToPath } from "node:url";
import { AppConfigSchema, ClientEntrySchema, createApp, defineModule, InMemoryClientRepository, InMemoryUserRepository, memoryRefreshTokenFamilyStoreModule, terminalErrorHandler, } from "@o3co/auth-provider-core";
import { createFakeIdp } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import express from "express";
import helmet from "helmet";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { buildModules } from "#/buildModules.mjs";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "#/configPath.mjs";
import { googleFederationConfigModule, oidcFederationConfigModule } from "#/modules.mjs";
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
export const SINGLE_ENV = {
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
export const MULTI_ENV = {
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
export function resolveConfig(env, referenceConfs = []) {
    const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
    const read = (path) => parseFile(path, { env: { ...env } });
    const layered = [
        applicationConfPath,
        ...referenceConfs,
        resolveLibraryReferenceConfPath(),
    ].reduce((config, path) => config.withFallback(read(path)), read(envConfPath));
    const resolved = validate(layered, AppConfigSchema);
    const federations = resolved.federations;
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
    };
}
// ---------------------------------------------------------------------------
// Registrations
// ---------------------------------------------------------------------------
export const WEB = { id: "web", secret: "web-secret", redirectUri: "https://rp.test/cb" };
export const M2M = { id: "m2m", secret: "m2m-secret" };
export const WORKER = {
    id: "worker",
    secret: "worker-secret",
    redirectUri: "https://worker.test/connected",
};
/** Not first-party: `/authorize` sends its user through the consent step. */
export const THIRD = {
    id: "third",
    secret: "third-secret",
    redirectUri: "https://third.test/cb",
};
export const ALICE = { username: "alice", password: "correct-horse-battery", sub: "u-alice" };
/** The subjects the fake IdPs sign in, as the Store has them linked. */
const OIDC_SUB = "idp-sub";
const GOOGLE_SUB = "google-sub";
const clientEntries = (extra = {}) => new Map([
    ...Object.entries(extra).map(([id, entry]) => [id, ClientEntrySchema.parse(entry)]),
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
const testRepositoriesModule = (extraClients = {}, extraUsers = {}) => defineModule({
    name: "test:repositories",
    provides: {
        clientRepository: () => new InMemoryClientRepository(clientEntries(extraClients)),
        userRepository: () => new InMemoryUserRepository(new Map([
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
        ])),
    },
});
let upstreams;
/**
 * The two fake upstreams, made once per test file — each generates an RSA key,
 * and a login's state lives in the authorization it recorded, so boots can
 * share them — and put back as they were made before every boot (`compose`
 * calls this). A test may set a fake's knobs for its own boot; it may not
 * rotate a fake's key, which cannot be put back, and the next boot refuses to
 * run if one did.
 */
export async function sharedUpstreams() {
    upstreams ??= createUpstreams().then((fakes) => ({
        fakes,
        reset: resettable(fakes.oidc, fakes.google),
    }));
    const { fakes, reset } = await upstreams;
    reset();
    return fakes;
}
/**
 * Snapshots each fake's settings — every property that is not a function —
 * and returns what puts them back: primitives reassigned, objects restored in
 * place (a fake may hold its own reference to one), recorded requests
 * cleared. A fake's signing key is checked, not restored: a rotated key is
 * refused.
 *
 * What a fake keeps in its closure is not restored either: core's fake IdP
 * remembers whether consent was granted (`consentGranted`), how many codes it
 * issued (`codesIssued`) and every authorization it recorded. Codes and
 * authorizations are keyed per login, so a later boot's login is unaffected;
 * consent is not, and it decides Google's refresh token only under
 * `refreshTokenOnlyOnConsent`. That knob is therefore forbidden on a shared
 * fake — the next reset refuses to run if a test set it; a test that needs it
 * makes a fake of its own with `createFakeIdp`.
 */
export function resettable(...fakes) {
    const snapshots = fakes.map((fake) => ({
        fake: fake,
        clone: new Map(Object.entries(fake)
            .filter(([name, value]) => typeof value !== "function" && name !== "requests")
            .map(([name, value]) => [name, structuredClone(value)])),
        kid: currentKidOf(fake),
    }));
    return () => {
        for (const { fake, clone, kid } of snapshots) {
            if (fake.refreshTokenOnlyOnConsent === true) {
                throw new Error("a test set refreshTokenOnlyOnConsent on a shared fake upstream: the consent it reads is closure state no reset restores; make a fake of its own instead");
            }
            if (currentKidOf(fake) !== kid) {
                throw new Error("a test rotated a shared fake upstream's key: the fakes are shared by every boot in the file; make a fake of its own instead");
            }
            for (const [name, original] of clone) {
                const current = fake[name];
                if (typeof current === "object" && current !== null && !Array.isArray(current)) {
                    for (const key of Object.keys(current))
                        delete current[key];
                    Object.assign(current, structuredClone(original));
                }
                else {
                    fake[name] = structuredClone(original);
                }
            }
            const requests = fake.requests;
            if (Array.isArray(requests))
                requests.splice(0);
        }
    };
}
const currentKidOf = (fake) => {
    const currentKid = fake.currentKid;
    return typeof currentKid === "function" ? currentKid() : undefined;
};
async function createUpstreams() {
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
 * What one of the template's config bridges provides for `config`. Read
 * through a record, not the typed slot: a program that loads this file without
 * a federation package's ComponentMap augmentation (`tools/composition` does)
 * has no key to name.
 */
const bridged = (module, slot, config) => {
    const provider = module.provides?.[slot];
    if (typeof provider !== "function")
        throw new Error(`${module.name} provides no ${slot}`);
    return provider({ config });
};
/**
 * The two federation config slots, read by the template's own bridges
 * (`oidcFederationConfigModule`, `googleFederationConfigModule`), with each
 * adapter's `fetch` pointed at its fake upstream. Only for the federations the
 * config enables — which is when `buildModules` lists the bridges.
 */
async function federationOverrides(config, upstreams) {
    const overrides = {};
    const modules = buildModules(config).map((m) => m.name);
    if (modules.includes(oidcFederationConfigModule.name)) {
        const oidc = bridged(oidcFederationConfigModule, "oidcFederationConfigs", config);
        overrides.oidcFederationConfigs = Object.fromEntries(Object.entries(oidc).map(([name, entry]) => [
            name,
            { ...entry, fetch: upstreams.oidc.fetch },
        ]));
    }
    if (modules.includes(googleFederationConfigModule.name)) {
        overrides.googleFederationConfig = {
            ...bridged(googleFederationConfigModule, "googleFederationConfig", config),
            fetch: upstreams.google.fetch,
        };
    }
    return overrides;
}
/** A `Logger` that records every call, its children's included, in one list. */
export function createRecordingLogger() {
    const lines = [];
    const make = (bindings) => {
        const at = (level) => (...args) => {
            const [first, ...rest] = args;
            lines.push({
                level,
                args: typeof first === "object" && first !== null && Object.keys(bindings).length > 0
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
        };
    };
    return Object.assign(make({}), { lines });
}
/** What a store adapter's client throws when its connection is refused. */
const connectionRefused = () => Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:6379"), { code: "ECONNREFUSED" });
/** Every method of `target` rejects while `outage.down`, and is the real one otherwise. */
function failWhileDown(target, outage) {
    return new Proxy(target, {
        get(object, property) {
            const value = Reflect.get(object, property, object);
            if (typeof value !== "function")
                return value;
            return (...args) => outage.down
                ? Promise.reject(connectionRefused())
                : value.apply(object, args);
        },
    });
}
/**
 * `modules` with the provider of `slot` wrapped by {@link failWhileDown}: the
 * real module, named and declared as it is, handing out the real store.
 */
function withOutage(modules, slot, outage) {
    let found = false;
    const wrapped = modules.map((module) => {
        const provides = module.provides;
        const provider = provides?.[slot];
        if (provider === undefined)
            return module;
        found = true;
        return {
            ...module,
            provides: {
                ...provides,
                [slot]: async (deps) => failWhileDown((await provider(deps)), outage),
            },
        };
    });
    if (!found)
        throw new Error(`no module in the composition provides ${slot}`);
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
/** The module list the template boots for `config`, as `app.mts` builds it. */
export function composedModules(config, options = {}) {
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
    if (options.outage)
        modules = withOutage(modules, options.outage.slot, options.outage.outage);
    if (options.order === REVERSED)
        modules = [modules[0], ...modules.slice(1).reverse()];
    return modules;
}
/**
 * Boots the composition and mounts it as `app.mts` does: `helmet`, the
 * composed router, and the terminal error handler last (unless
 * `terminalErrorHandler` is `false`), all on one logger that is also the
 * boot's `logger` component.
 */
export async function compose(options = {}) {
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
        },
    });
    const app = express();
    app.set("trust proxy", config.http.trustProxy);
    app.use(helmet({
        contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
    }));
    app.use(handle.router);
    if (options.terminalErrorHandler !== false)
        app.use(terminalErrorHandler(logger));
    return { app, handle, config, modules, logger, upstreams: fakes };
}
// ---------------------------------------------------------------------------
// Flows
// ---------------------------------------------------------------------------
export const basic = (client) => `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`;
const cookiesOf = (res) => res.headers["set-cookie"] ?? [];
/** The browser half: a CSRF pair, then the password login. */
export async function login(app) {
    const csrf = await request(app).get("/session/csrf");
    const res = await request(app)
        .post("/session/login")
        .set("Cookie", cookiesOf(csrf))
        .set(csrf.body.header_name, csrf.body.csrf_token)
        .type("form")
        .send({ username: ALICE.username, password: ALICE.password });
    return { res, cookies: res.status === 200 ? cookiesOf(res) : cookiesOf(csrf) };
}
export const PKCE = (() => {
    const verifier = randomBytes(32).toString("base64url");
    return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
})();
export function authorize(app, cookies, client = WEB) {
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
export const codeFrom = (res) => {
    const code = new URL(res.headers.location).searchParams.get("code");
    if (code === null)
        throw new Error(`no code in ${res.status} ${res.headers.location}`);
    return code;
};
export function redeem(app, code) {
    return request(app).post("/oauth/token").set("Authorization", basic(WEB)).type("form").send({
        grant_type: "authorization_code",
        code,
        redirect_uri: WEB.redirectUri,
        code_verifier: PKCE.verifier,
    });
}
/** Log in, authorize with PKCE, redeem: the web client's tokens. */
export async function webTokens(app) {
    const { cookies } = await login(app);
    const res = await redeem(app, codeFrom(await authorize(app, cookies)));
    if (res.status !== 200)
        throw new Error(`code exchange answered ${res.status}`);
    return res.body;
}
/**
 * Start a federated login and play the upstream. What comes back sends the
 * callback when called — a function, because a supertest request is a
 * thenable, and returning one from an async function would send it.
 */
export async function federatedCallback(app, name, upstream) {
    const start = await request(app).get(`/session/oauth/federation/${name}`);
    if (start.status !== 302)
        throw new Error(`federation start answered ${start.status}`);
    const answer = upstream.authorize(start.headers.location);
    return () => request(app)
        .get(`/session/oauth/federation/${name}/callback`)
        .set("Cookie", cookiesOf(start))
        .query({ code: answer.code, state: answer.state ?? "", iss: answer.iss });
}
export function lodgeGrant(app) {
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
];
/**
 * What RFC 8414 §2 and OpenID Connect Discovery §3 require of the document
 * this composition serves, and what each advertised URL must be: https, on
 * the issuer's origin.
 */
export function expectValidMetadata(doc) {
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
            const url = new URL(value);
            expect(url.origin, field).toBe(ISSUER);
            expect(url.search + url.hash, field).toBe("");
        }
        if (field.endsWith("_supported") && Array.isArray(value)) {
            expect(value.length, field).toBeGreaterThan(0);
            for (const entry of value)
                expect(typeof entry, field).toBe("string");
            expect(new Set(value).size, `${field} repeats a value`).toBe(value.length);
        }
    }
    expect(doc.response_types_supported).toEqual(["code"]);
    expect(doc.code_challenge_methods_supported).toEqual(["S256"]);
}
// ---------------------------------------------------------------------------
// Known defects
// ---------------------------------------------------------------------------
const templateManifest = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
/** The template's `@o3co/auth-provider-*` dependencies, as its `package.json` names them. */
export const TEMPLATE_DEPENDENCIES = Object.keys(templateManifest.dependencies).filter((name) => name.startsWith("@o3co/auth-provider-"));
/**
 * Inside the monorepo the template names its siblings `workspace:*`; a
 * scaffold, and CI's packed-tarball run, name versions or tarballs.
 */
export const inMonorepo = templateManifest.dependencies["@o3co/auth-provider-core"]?.startsWith("workspace:") === true;
/**
 * A contract the composition breaks today. `it.fails` in the monorepo, where
 * the fix lands beside this file and flips it; skipped in a scaffold, which
 * pins released packages and would otherwise turn red on the upgrade that
 * carries the fix.
 */
export const knownDefect = (inMonorepo ? it.fails : it.skip);
// ---------------------------------------------------------------------------
// Manifests
// ---------------------------------------------------------------------------
/** The names a module contributes under `kind`: its own name for a list-shaped kind. */
export const contributionNames = (module, kind) => {
    const contribution = module.contributes?.[kind];
    if (contribution === undefined)
        return [];
    return Array.isArray(contribution) ? [module.name] : Object.keys(contribution);
};
// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------
export const KIB = 1024;
export const JSON_TYPE = "application/json";
export const FORM_TYPE = "application/x-www-form-urlencoded";
/** A POST with its `Content-Length` declared, through supertest. */
export const withLength = async (app, path, contentType, body, headers = {}) => {
    const res = await request(app)
        .post(path)
        .set(headers)
        .set("Content-Type", contentType)
        .send(body);
    return { status: res.status, body: res.body };
};
/**
 * A POST whose body has no `Content-Length` — `Transfer-Encoding: chunked`,
 * one KiB a chunk — so only a parser's own running count can bound it.
 * supertest always sets the length, hence a raw request on a real socket.
 */
export const postChunked = async (app, path, contentType, body, headers = {}) => {
    const server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
        const { port } = server.address();
        return await new Promise((resolve, reject) => {
            let answered = false;
            const req = http.request({
                host: "127.0.0.1",
                port,
                path,
                method: "POST",
                // One connection per request, closed after it: nothing keeps the server open.
                agent: false,
                headers: { ...headers, "content-type": contentType, "transfer-encoding": "chunked" },
            }, (res) => {
                answered = true;
                let text = "";
                res.setEncoding("utf8");
                res.on("data", (chunk) => {
                    text += chunk;
                });
                res.on("end", () => {
                    let parsed = {};
                    try {
                        parsed = JSON.parse(text);
                    }
                    catch {
                        // Not JSON: the status carries the verdict.
                    }
                    resolve({ status: res.statusCode ?? 0, body: parsed });
                });
            });
            // A server that answers 413 mid-body may close the socket while the
            // rest is still being written; that is the answer, not a failure.
            req.on("error", (err) => {
                if (!answered)
                    reject(err);
            });
            for (let at = 0; at < body.length; at += KIB)
                req.write(body.slice(at, at + KIB));
            req.end();
        });
    }
    finally {
        await new Promise((resolve) => server.close(() => resolve()));
    }
};
export const TRANSFERS = [
    ["with Content-Length", withLength],
    ["chunked", postChunked],
];
/** A JSON body: `fields`, and `bytes` of padding. */
export const padJson = (bytes, fields = {}) => JSON.stringify({ ...fields, pad: "a".repeat(bytes) });
/** A form body: `fields`, and `bytes` of padding. */
export const padForm = (bytes, fields) => `${fields}&pad=${"a".repeat(bytes)}`;
/**
 * What a parser's refusal of an oversized body is answered with on a route
 * of the composed router — by core's terminal handler, which ends it.
 */
export const TOO_LARGE = { error: "invalid_request", error_description: "body_too_large" };
/** The same defect text for every predicate that depends on the one missing line. */
export const withoutTheLine = (defect) => ({
    "one-error-line": defect,
    "store-field": `no error line to carry it: ${defect}`,
    projection: `no error line to carry it: ${defect}`,
});
/** The object argument of a log line, when the line is object-first. */
export const fieldsOf = (line) => typeof line?.args[0] === "object" && line.args[0] !== null
    ? line.args[0]
    : {};
/**
 * One `describe` per case: the case's composition is booted and its flow run
 * once, the store taken down at the step under test, and each predicate is its
 * own test — a plain `it` where the composition keeps it, `knownDefect` where
 * it does not.
 */
export function describeOutages(title, cases, boot) {
    describe(title, () => {
        for (const c of cases) {
            describe(`${c.module}: ${c.slot} down at ${c.surface}`, () => {
                let res;
                let lines = [];
                let tookDown = false;
                beforeAll(async () => {
                    let composition;
                    let from = -1;
                    let down = false;
                    const outage = {
                        get down() {
                            return down;
                        },
                        set down(value) {
                            if (value && from < 0)
                                from = composition?.logger.lines.length ?? 0;
                            down = value;
                        },
                    };
                    composition = await boot({ slot: c.slot, outage });
                    try {
                        res = await c.run(composition.app, outage, composition);
                        tookDown = from >= 0;
                        // Everything logged from the moment the store went down is the outage's.
                        lines = composition.logger.lines.slice(Math.max(from, 0));
                    }
                    finally {
                        await composition.handle.dispose();
                    }
                });
                const errors = () => lines.filter((line) => line.level === "error");
                const check = (predicate, name, assertion) => {
                    const defect = c.defects?.[predicate];
                    (defect === undefined ? it : knownDefect)(name, assertion);
                };
                // Plain whatever the case pins: a pinned predicate must fail for its
                // defect, not because the flow never reached the step under test.
                it("reaches the step under test and takes the store down there", () => {
                    expect(tookDown).toBe(true);
                });
                check("answer", "answers as an outage", () => {
                    if ("redirect" in c.answer) {
                        expect(res.status).toBe(302);
                        const location = new URL(res.headers.location);
                        expect(`${location.origin}${location.pathname}`).toBe(c.answer.redirect);
                        expect(location.searchParams.get("error")).toBe(c.answer.error);
                    }
                    else {
                        expect(res.status).toBe(c.answer.status);
                        expect(res.body.error).toBe(c.answer.error);
                        expect(res.headers["www-authenticate"]).toBeUndefined();
                    }
                });
                check("one-error-line", "logs exactly one error line, object-first with a name", () => {
                    expect(errors().map((line) => line.args[1] ?? line.args[0]), "exactly one error line").toHaveLength(1);
                    expect(typeof errors()[0]?.args[0]).toBe("object");
                    expect(typeof errors()[0]?.args[1]).toBe("string");
                });
                if (c.event !== undefined) {
                    const event = c.event;
                    check("event-name", `names it ${event}`, () => {
                        expect(errors().map((line) => line.args[1])).toEqual([event]);
                    });
                }
                if (c.storeFieldNotRequired === undefined) {
                    check("store-field", "names what failed (store, step or site)", () => {
                        const fields = fieldsOf(errors()[0]);
                        expect(["store", "step", "site"].filter((field) => typeof fields[field] === "string")).not.toEqual([]);
                    });
                }
                check("projection", "carries the error's projection", () => {
                    const err = fieldsOf(errors()[0]).err;
                    expect(err).toMatchObject({ name: expect.any(String) });
                    expect(err).not.toBeInstanceOf(Error);
                });
                check("no-warn", "writes no warn line for it", () => {
                    const warns = lines
                        .filter((line) => line.level === "warn")
                        .map((line) => (typeof line.args[1] === "string" ? line.args[1] : String(line.args[0])))
                        .filter((event) => !(c.unrelatedWarns ?? []).includes(event));
                    expect(warns).toEqual([]);
                });
            });
        }
    });
}
