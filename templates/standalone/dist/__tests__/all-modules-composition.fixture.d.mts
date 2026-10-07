import { type AppConfig, createApp, type Logger, type Module } from "@o3co/auth-provider-core";
import { type FakeIdp } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { it } from "vitest";
export declare const ISSUER = "https://auth.test";
/** Where a federated login lands the browser when the start carried no `redirect_to`. */
export declare const FEDERATION_LANDING = "https://app.test/home";
/**
 * One replica, every store in memory, every feature the template can switch
 * on switched on: the four token grants, the consent step with Client ID
 * Metadata Documents, federation grants, the Google federation and the
 * shipped generic OIDC one.
 */
export declare const SINGLE_ENV: Readonly<Record<string, string>>;
/**
 * The same deployment on more than one replica: every shared store on Redis,
 * express-session's own included (the umbrella E2E's shape).
 */
export declare const MULTI_ENV: Readonly<Record<string, string>>;
/** The grant connection the federation-grant flows use, on the shipped `oidc` federation. */
export declare const CONNECTION = "calendar";
/**
 * The shipped HOCON under `env`, with what has no environment form laid over
 * it: the federations' landing page, the grant key ring and one grant
 * connection. `referenceConfs` — other packages' `reference.conf` files — are
 * layered between `application.conf` and core's, as a deployment layers them.
 */
export declare function resolveConfig(env: Readonly<Record<string, string>>, referenceConfs?: readonly string[]): AppConfig;
export declare const WEB: {
    readonly id: "web";
    readonly secret: "web-secret";
    readonly redirectUri: "https://rp.test/cb";
};
export declare const M2M: {
    readonly id: "m2m";
    readonly secret: "m2m-secret";
};
export declare const WORKER: {
    readonly id: "worker";
    readonly secret: "worker-secret";
    readonly redirectUri: "https://worker.test/connected";
};
/** Not first-party: `/authorize` sends its user through the consent step. */
export declare const THIRD: {
    readonly id: "third";
    readonly secret: "third-secret";
    readonly redirectUri: "https://third.test/cb";
};
export declare const ALICE: {
    username: string;
    password: string;
    sub: string;
};
export interface Upstreams {
    readonly oidc: FakeIdp;
    readonly google: FakeIdp;
}
/**
 * The two fake upstreams, made once per test file — each generates an RSA key,
 * and a login's state lives in the authorization it recorded, so boots can
 * share them — and put back as they were made before every boot (`compose`
 * calls this). A test may set a fake's knobs for its own boot; it may not
 * rotate a fake's key, which cannot be put back, and the next boot refuses to
 * run if one did.
 */
export declare function sharedUpstreams(): Promise<Upstreams>;
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
export declare function resettable(...fakes: readonly object[]): () => void;
export interface LogLine {
    readonly level: "trace" | "debug" | "info" | "warn" | "error" | "fatal";
    readonly args: readonly unknown[];
}
export interface RecordingLogger extends Logger {
    readonly lines: LogLine[];
}
/** A `Logger` that records every call, its children's included, in one list. */
export declare function createRecordingLogger(): RecordingLogger;
/** A switch an outage wrapper reads on every call. */
export interface Outage {
    down: boolean;
}
/** The order `buildModules` lists the modules in. */
export declare const AS_LISTED = "as listed";
/**
 * Every module after the first in reverse. The first, express-session's
 * middleware, is placed by list position alone (`buildModules` says so), so
 * it stays first; everything else changes place.
 */
export declare const REVERSED = "reversed";
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
    readonly outage?: {
        readonly slot: string;
        readonly outage: Outage;
    };
    /** Keep the shipped Redis refresh-token family store (the `multi` boot). */
    readonly shippedRefreshTokenFamilyStore?: boolean;
    /**
     * Mount core's terminal error handler after the composed router again, as
     * `app.mts` does for its host routes (the default). `false` mounts the
     * router alone, as a composition root that copies nothing of `app.mts`
     * does.
     */
    readonly terminalErrorHandler?: boolean;
}
/** The module list the template boots for `config`, as `app.mts` builds it. */
export declare function composedModules(config: AppConfig, options?: ComposeOptions): Module[];
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
 * composed router, and the terminal error handler last (unless
 * `terminalErrorHandler` is `false`), all on one logger that is also the
 * boot's `logger` component.
 */
export declare function compose(options?: ComposeOptions): Promise<Composition>;
export declare const basic: (client: {
    id: string;
    secret: string;
}) => string;
declare const cookiesOf: (res: request.Response) => string[];
/** The browser half: a CSRF pair, then the password login. */
export declare function login(app: express.Express): Promise<{
    readonly res: request.Response;
    readonly cookies: string[];
}>;
export declare const PKCE: {
    verifier: string;
    challenge: string;
};
export declare function authorize(app: express.Express, cookies: readonly string[], client?: {
    id: string;
    redirectUri: string;
}): request.Test;
export declare const codeFrom: (res: request.Response) => string;
export declare function redeem(app: express.Express, code: string): request.Test;
/** Log in, authorize with PKCE, redeem: the web client's tokens. */
export declare function webTokens(app: express.Express): Promise<Record<string, string>>;
/**
 * Start a federated login and play the upstream. What comes back sends the
 * callback when called — a function, because a supertest request is a
 * thenable, and returning one from an async function would send it.
 */
export declare function federatedCallback(app: express.Express, name: "oidc" | "google", upstream: FakeIdp): Promise<() => request.Test>;
export declare function lodgeGrant(app: express.Express): request.Test;
export { cookiesOf };
export declare const DISCOVERY_PATHS: readonly ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"];
/**
 * What RFC 8414 §2 and OpenID Connect Discovery §3 require of the document
 * this composition serves, and what each advertised URL must be: https, on
 * the issuer's origin.
 */
export declare function expectValidMetadata(doc: Record<string, unknown>): void;
/** The template's `@o3co/auth-provider-*` dependencies, as its `package.json` names them. */
export declare const TEMPLATE_DEPENDENCIES: readonly string[];
/**
 * Inside the monorepo the template names its siblings `workspace:*`; a
 * scaffold, and CI's packed-tarball run, name versions or tarballs.
 */
export declare const inMonorepo: boolean;
/**
 * A contract the composition breaks today. `it.fails` in the monorepo, where
 * the fix lands beside this file and flips it; skipped in a scaffold, which
 * pins released packages and would otherwise turn red on the upgrade that
 * carries the fix.
 */
export declare const knownDefect: typeof it;
/** The names a module contributes under `kind`: its own name for a list-shaped kind. */
export declare const contributionNames: (module: Module, kind: string) => string[];
export declare const KIB = 1024;
export declare const JSON_TYPE = "application/json";
export declare const FORM_TYPE = "application/x-www-form-urlencoded";
export type Send = (app: express.Express, path: string, contentType: string, body: string, headers?: Record<string, string>) => Promise<{
    status: number;
    body: Record<string, unknown>;
}>;
/** A POST with its `Content-Length` declared, through supertest. */
export declare const withLength: Send;
/**
 * A POST whose body has no `Content-Length` — `Transfer-Encoding: chunked`,
 * one KiB a chunk — so only a parser's own running count can bound it.
 * supertest always sets the length, hence a raw request on a real socket.
 */
export declare const postChunked: Send;
export declare const TRANSFERS: ReadonlyArray<readonly [string, Send]>;
/** A JSON body: `fields`, and `bytes` of padding. */
export declare const padJson: (bytes: number, fields?: Record<string, unknown>) => string;
/** A form body: `fields`, and `bytes` of padding. */
export declare const padForm: (bytes: number, fields: string) => string;
/**
 * What a parser's refusal of an oversized body is answered with on a route
 * of the composed router — by core's terminal handler, which ends it.
 */
export declare const TOO_LARGE: {
    error: string;
    error_description: string;
};
/**
 * The parts of the #685 outage rule, each checked on its own so a case pins
 * only what is broken and asserts the rest:
 *
 * - `answer` — the status and error code (a redirect's location and code);
 * - `one-error-line` — exactly one error-level line, object-first with a name;
 * - `event-name` — that name (checked only where the case names one);
 * - `store-field` — a `store`, `step` or `site` field naming what failed;
 * - `projection` — its `err` is core's `loggableError` projection;
 * - `no-warn` — no warn line for the outage beside it.
 */
export type OutagePredicate = "answer" | "one-error-line" | "event-name" | "store-field" | "projection" | "no-warn";
export interface OutageCase<C extends Composition = Composition> {
    /** The module whose route answers. */
    readonly module: string;
    /** The ComponentMap slot whose store goes down. */
    readonly slot: string;
    readonly surface: string;
    /** Drives the route, taking the store down at the step under test. */
    readonly run: (app: express.Express, outage: Outage, c: C) => Promise<request.Response>;
    readonly answer: {
        readonly status: number;
        readonly error?: string;
    } | {
        readonly redirect: string;
        readonly error: string;
    };
    /**
     * The one line's name. Absent where the composition writes no such line
     * today — and then `event-name` is not checked at all, so the fix that
     * flips such a row adds its `event` in the same change.
     */
    readonly event?: string;
    /** Warn lines this route writes whatever the store does — not the outage's. */
    readonly unrelatedWarns?: readonly string[];
    /**
     * Why `store-field` does not apply: the line is not an outage's 503, the
     * request succeeds. Absent, the predicate is checked.
     */
    readonly storeFieldNotRequired?: string;
    /** The predicates the composition breaks today, each naming its defect. */
    readonly defects?: Partial<Record<OutagePredicate, string>>;
}
/** The same defect text for every predicate that depends on the one missing line. */
export declare const withoutTheLine: (defect: string) => Pick<Record<OutagePredicate, string>, "one-error-line" | "store-field" | "projection">;
/** The object argument of a log line, when the line is object-first. */
export declare const fieldsOf: (line: LogLine | undefined) => Record<string, unknown>;
/**
 * One `describe` per case: the case's composition is booted and its flow run
 * once, the store taken down at the step under test, and each predicate is its
 * own test — a plain `it` where the composition keeps it, `knownDefect` where
 * it does not.
 */
export declare function describeOutages<C extends Composition>(title: string, cases: readonly OutageCase<C>[], boot: (outage: {
    readonly slot: string;
    readonly outage: Outage;
}) => Promise<C>): void;
//# sourceMappingURL=all-modules-composition.fixture.d.mts.map