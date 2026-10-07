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
 * The module of the RFC 8628 device authorization grant. Enabled, it
 * contributes the `urn:ietf:params:oauth:grant-type:device_code` grant,
 * `POST /oauth/device_authorization` (where a device starts),
 * `POST /oauth/device/verification` (where the user answers),
 * `device_authorization_endpoint` in discovery (RFC 8628 §4), and the three
 * actions verification admits (`DEVICE_GRANT_ADMISSION_ACTIONS`).
 *
 * One module, built from nothing, switched by its own section: the switch,
 * `device-grant.enabled`, is read from `device-grant {}` as boot parsed it
 * (`section.isEnabled`), and an absent section or key is off. Off, the
 * module registers nothing — no grant (so `grant_types_supported` does not
 * name it), action, route, discovery field, budget, requirement or absence
 * policy — and requires nothing. The section's defaults live in the
 * package's `config/reference.conf` alone. A key still written at
 * `oauth.deviceAuthorization`, the section's old path, refuses boot naming
 * the new one; `store`, at either path, refuses boot as removed.
 *
 * It reads no whole configuration. What it needs of `oauth {}` — the issuer,
 * the access-token lifetime and `requireEmailVerified` — it reads from the
 * `oauthTokenSettings` slot, required while the grant is on: the oauth
 * module provides it, and a composition without that module fills it. The
 * destination policy a client's `jwksUri` is fetched under is core's
 * `outboundPolicy` slot.
 *
 * Enabled, boot is refused without each setting and slot the grant needs to
 * be safe; the `require*` helpers below say why. The user code's attempt
 * limit, `device-grant.rateLimit`, is counted by core's attempt guard on the
 * `attemptCounter` slot, never by a rate limiter; the `rateLimiter` slot,
 * when wired, throttles `/oauth/device_authorization` alone.
 *
 * The verification endpoint authorises on the session cookie, which makes it
 * a CSRF target (RFC 8628 §5.4 remote phishing: a foreign page auto-submits
 * `approve` for the attacker's `user_code`), so it accepts JSON only — a form
 * POST needs no preflight — and runs the session module's `csrfGuard` on the
 * whole route.
 */

import {
	AUDIT_SINK_ABSENCE_POLICY,
	checkOAuthTokenSettings,
	coerceBooleanFromEnv,
	consoleLogger,
	createOutboundFetch,
	createRateLimitGuard,
	defineModule,
	guardedRead,
	loggableError,
	MAX_ATTEMPT_WINDOW_SECONDS,
	type ProviderDeps,
	verifierLimitClaim,
	wholeNumberInRangeFromEnv,
} from "@o3co/auth-provider-core";
import { createClientAuthMiddleware } from "@o3co/auth-provider-oauth";
import express, { type ErrorRequestHandler, type RequestHandler, type Response } from "express";
import { z } from "zod";
import { DEVICE_GRANT_ADMISSION_ACTIONS } from "./admissionActions.mjs";
import {
	createDeviceAuthorizationHandler,
	DEVICE_CODE_LIFETIME_SECONDS,
	DEVICE_POLLING_INTERVAL_SECONDS,
} from "./deviceAuthorizationEndpoint.mjs";
import { createDeviceCodeGrant } from "./grant.mjs";
import { DEVICE_AUTHORIZATION_RATE_LIMIT_PREFIX, DEVICE_CODE_GRANT_TYPE } from "./types.mjs";
import {
	DEVICE_VERIFICATION_ATTEMPT_TAG,
	readVerificationAttemptSpec,
} from "./verificationAttempts.mjs";
import {
	createDeviceVerificationHandler,
	requireSessionLifecycleStore,
} from "./verificationEndpoint.mjs";

/**
 * `device-grant.rateLimit` — the attempts RFC 8628 §5.1 sizes the user code
 * against. The floor of 1 is load-bearing: a zero limit locks every user out.
 * The window is at most a day, the longest an attempt counter takes.
 */
const rateLimitSpecSchema = z
	.object({
		limit: wholeNumberInRangeFromEnv(1),
		windowSeconds: wholeNumberInRangeFromEnv(1, MAX_ATTEMPT_WINDOW_SECONDS),
	})
	.strict();

/**
 * The schema of `device-grant {}`, the module's own section. Strict at every
 * level: a key it does not declare refuses boot. Each scalar leaf reads the
 * string an environment variable carries. It fills no default: the package's
 * `config/reference.conf` ships every value, so a key a composition leaves
 * out of a section it writes refuses boot, naming the key. Absent, the
 * section is `undefined`, which the switch reads as off.
 */
export const deviceGrantConfigSchema = z
	.object({
		/** The module's switch: on only when true; absent is off. */
		enabled: coerceBooleanFromEnv.optional(),
		/**
		 * The page where the end user types the code. No default: the page
		 * belongs to the deployment, and a guessed URL is one the device would
		 * display to users who cannot use it.
		 */
		verificationUri: z.string().url().optional(),
		/**
		 * Emit `verification_uri_complete` (RFC 8628 §3.3.1). Shipped off —
		 * §5.4 warns that removing the typing step removes the proof that the
		 * device is in the user's possession, which is what makes remote
		 * phishing hard.
		 */
		verificationUriComplete: coerceBooleanFromEnv,
		/**
		 * §5.4: "long enough lifetime to be useable ... but sufficiently short
		 * to limit the usability of a code obtained for phishing".
		 */
		codeLifetimeSeconds: wholeNumberInRangeFromEnv(
			DEVICE_CODE_LIFETIME_SECONDS.min,
			DEVICE_CODE_LIFETIME_SECONDS.max,
		),
		/** Advertised as `interval`; also what the store enforces. */
		pollingIntervalSeconds: wholeNumberInRangeFromEnv(
			DEVICE_POLLING_INTERVAL_SECONDS.min,
			DEVICE_POLLING_INTERVAL_SECONDS.max,
		),
		/**
		 * The verification endpoint's attempt limit per authenticated subject,
		 * counted on the `attemptCounter` slot's counter, never a rate
		 * limiter's.
		 */
		rateLimit: rateLimitSpecSchema,
	})
	.strict()
	.optional();

/** The `device-grant` section as its schema leaves it, when it is written. */
type DeviceAuthorizationConfigSlice = NonNullable<z.output<typeof deviceGrantConfigSchema>>;

const REQUIRES = [
	"clientRepository",
	"keyStore",
	// Session admission's synthetic key: the verification endpoint admits
	// each action through it. The planner always fills it.
	"sessionRequirementResolver",
	// Counting verification attempts per process is refused under `multi`, so
	// a mode read as absent must not lift that. Boot always fills it.
	"deploymentMode",
	// What the oauth module provides of `oauth {}`: the issuer, the
	// access-token lifetime and `requireEmailVerified`. A composition without
	// that module fills it.
	"oauthTokenSettings",
	// The destination policy of `core.outbound`, which a `private_key_jwt`
	// client's `jwksUri` is fetched under. Boot always fills it.
	"outboundPolicy",
] as const;
// `replaySeenSet` records a client assertion's single-use `jti`. Optional as
// on the OAuth router: without it a `private_key_jwt` request is
// `server_error`, never an assertion accepted unchecked.
const OPTIONAL = [
	// Read by the grant and both endpoints; required once the grant is
	// enabled (`requireDeviceCodeStore`), unused while it is off.
	"deviceCodeStore",
	// The counter the verification's attempt limit runs on. Without one it is
	// counted per process, where the deployment mode allows it.
	"attemptCounter",
	// The deployment's abuse control on `/oauth/device_authorization`. Core
	// attaches its absence policy: unfilled, `core.declaredAbsent` lists it.
	"rateLimiter",
	"replaySeenSet",
	"logger",
	"auditSink",
	// Read by the verification endpoint, which approves only from a live
	// `UserSession`; required once the grant is enabled
	// (`requireUserSessionStore`), unused while it is off.
	"userSessionStore",
	// The subject's sessions boundary: read by the verification endpoint
	// (a session it covers) and the grant (an approval it covers).
	"subjectRevocation",
	// The session lifecycle port the verification endpoint's admission reads
	// after a live record: a session closing or closed approves nothing.
	// Required beside `userSessionStore` once the grant is enabled
	// (`requireSessionLifecycleStore`).
	"sessionLifecycleStore",
	// The session module's CSRF policy, run on the whole verification route.
	// Required once the grant is enabled (`requireCsrfMiddleware`).
	"csrfGuard",
	// Consulted by the grant at the poll, when wired.
	"grantPolicy",
] as const;

/**
 * The deps every contribution of {@link deviceAuthorizationGrantModule}
 * receives: exactly its `requires` / `optional`, typed.
 */
type Requires = (typeof REQUIRES)[number];
type Optional = (typeof OPTIONAL)[number];
export type DeviceGrantModuleDeps = ProviderDeps<Requires, Optional>;

/**
 * What this module reads of `oauth {}`: the `oauthTokenSettings` slot, held
 * to its contract by `checkOAuthTokenSettings`. Boot holds the slot to it
 * before any reader; the check here refuses a value a direct caller hands
 * in, naming the member it lacks.
 */
const tokenSettings = (deps: DeviceGrantModuleDeps) =>
	checkOAuthTokenSettings(deps.oauthTokenSettings);

/**
 * The section a factory is handed. Boot runs a factory only while the
 * switch answers true, which an absent section does not; a factory called
 * directly with none is refused, naming the section.
 */
const enabledSection = (
	section: DeviceAuthorizationConfigSlice | undefined,
): DeviceAuthorizationConfigSlice => {
	if (section === undefined) {
		throw new Error(
			"deviceAuthorizationGrantModule: a factory ran with no device-grant section; the grant is off without one.",
		);
	}
	return section;
};

const requireVerificationUri = (slice: DeviceAuthorizationConfigSlice): string => {
	const uri = slice.verificationUri;
	if (typeof uri !== "string" || uri === "") {
		throw new Error(
			"deviceAuthorizationGrantModule: device-grant.enabled = true requires " +
				"device-grant.verificationUri. It is the page this " +
				"deployment serves for entering the code, and the device displays it " +
				"verbatim — there is nothing sensible to default it to.",
		);
	}
	return uri;
};

/** Both routes' body bound: the parsers' `limit`, and the check ahead of them. */
const BODY_LIMIT = "16kb";
const BODY_LIMIT_BYTES = 16 * 1024;

/**
 * Cache directives on every exit of both routes, mounted first so answers no
 * handler here writes (the throttle's 429, client authentication's 401, the
 * CSRF guard's 403) carry them too: a cached refusal reaches the next caller.
 */
const noStore: RequestHandler = (_req, res, next) => {
	res.set("Cache-Control", "no-store").set("Pragma", "no-cache");
	next();
};

/** An RFC 6749 §5.2 error body, with the same cache directives `noStore` sets. */
const answerError = (res: Response, status: number, error: string, description: string): void => {
	res
		.status(status)
		.set("Cache-Control", "no-store")
		.set("Pragma", "no-cache")
		.json({ error, error_description: description });
};

/** The one answer for a body over the bound, however it was found to be. */
const refuseTooLarge = (res: Response): void => {
	answerError(res, 413, "invalid_request", "body_too_large");
};

/**
 * Refuses a declared `Content-Length` over the bound before any of the body
 * is read. A chunked body is left to the parsers' `limit`, and
 * `parserRefusals` answers that refusal the same way.
 */
const withinBodyLimit: RequestHandler = (req, res, next) => {
	const declared = Number(req.headers["content-length"]);
	if (Number.isFinite(declared) && declared > BODY_LIMIT_BYTES) {
		refuseTooLarge(res);
		return;
	}
	next();
};

/**
 * Maps a body-parser refusal that is the caller's mistake (`http-errors` with
 * `expose: true` and a 4xx `status`) to its answer, else `null`. These must
 * not become 500s or error-level logs: on the verification route the parser
 * runs before the CSRF guard and any throttle, so anyone could fill the error
 * log. Fields are read through `guardedRead`: a throwing getter here would
 * replace the error `unexpectedErrors` receives.
 */
const callerMistake = (
	error: unknown,
): { readonly status: 400 | 413 | 415; readonly description: string } | null => {
	if (error === null || typeof error !== "object") return null;
	const exposed = guardedRead(error, "expose");
	const statused = guardedRead(error, "status");
	const typed = guardedRead(error, "type");
	if (exposed === null || statused === null || typed === null) return null;
	const [expose, status, type] = [exposed.value, statused.value, typed.value];
	if (expose !== true || typeof status !== "number" || status < 400 || status >= 500) return null;
	if (type === "entity.too.large" || type === "parameters.too.many") {
		return { status: 413, description: "body_too_large" };
	}
	if (type === "charset.unsupported" || type === "encoding.unsupported") {
		return { status: 415, description: "unsupported_encoding" };
	}
	return { status: 400, description: "malformed_body" };
};

/**
 * Answers the parsers' refusals as `callerMistake` classifies them, quoting
 * none of the body; anything else passes on to `unexpectedErrors`. It must be
 * mounted directly after the parsers: mounted last, it would treat an exposed
 * 4xx from a store or handler as a refused body.
 */
const parserRefusals: ErrorRequestHandler = (error, _req, res, next) => {
	const mistake = res.headersSent ? null : callerMistake(error);
	if (mistake === null) {
		next(error);
		return;
	}
	answerError(res, mistake.status, "invalid_request", mistake.description);
};

/**
 * The last error handler on both routes: `500 server_error`, logging only
 * core's `loggableError` projection (the raw error can carry request or store
 * data). Always JSON (RFC 8628 §3.2, RFC 6749 §5.2), never the host app's
 * error page.
 */
const unexpectedErrors =
	(logger: DeviceGrantModuleDeps["logger"]): ErrorRequestHandler =>
	(error, _req, res, next) => {
		if (res.headersSent) {
			next(error);
			return;
		}
		(logger ?? consoleLogger).error({ err: loggableError(error) }, "device_route_unexpected_error");
		answerError(res, 500, "server_error", "unexpected_error");
	};

/**
 * The middleware of the `csrfGuard` slot the session module provides — the
 * guard `/session/login` runs. Required when the grant is on: the
 * verification endpoint authorises on the session cookie and would otherwise
 * have no CSRF defence. Core holds the slot to its contract where boot fills
 * it, so the middleware is a request handler already.
 */
const requireCsrfMiddleware = (deps: DeviceGrantModuleDeps): RequestHandler => {
	const guard = deps.csrfGuard;
	if (guard === undefined) {
		throw new Error(
			"deviceAuthorizationGrantModule: device-grant.enabled = true requires a " +
				"csrfGuard component. POST /oauth/device/verification runs inside the end-user " +
				"session and is guarded by the same CSRF policy as /session/login — a signed " +
				"double-submit token, and an Origin/Referer check against " +
				"session.csrf.trustedOrigins — which the session module (sessionModule) provides; " +
				"without it the endpoint cannot be mounted safely. Install the session module, " +
				"or leave the grant disabled.",
		);
	}
	return guard.middleware;
};

/**
 * Presence check for the optional `deviceCodeStore` slot, read by the grant
 * and both endpoints: the grant cannot run without one, so there is no
 * absence to declare while it is on.
 */
const requireDeviceCodeStore = (
	deps: DeviceGrantModuleDeps,
): NonNullable<DeviceGrantModuleDeps["deviceCodeStore"]> => {
	if (deps.deviceCodeStore === undefined) {
		throw new Error(
			"deviceAuthorizationGrantModule: device-grant.enabled = true requires a " +
				"deviceCodeStore component. The grant has nowhere to record a pending " +
				"authorization, so no device could ever be authorized. Install " +
				"memoryDeviceCodeStoreModule (single replica only) or " +
				"redisDeviceCodeStoreModule, or leave the grant disabled.",
		);
	}
	return deps.deviceCodeStore;
};

/**
 * The verification endpoint reads the `UserSession` behind the cookie before
 * any action (see `verificationEndpoint.mts`), so the store is required when
 * the grant is on.
 */
const requireUserSessionStore = (
	deps: DeviceGrantModuleDeps,
): NonNullable<DeviceGrantModuleDeps["userSessionStore"]> => {
	if (deps.userSessionStore === undefined) {
		throw new Error(
			"deviceAuthorizationGrantModule: device-grant.enabled = true requires a " +
				"userSessionStore component. POST /oauth/device/verification approves only from " +
				"the live UserSession behind the cookie's sid: the device token an approval leads " +
				"to carries no sid and no family_id, so no logout reaches it afterwards, and a " +
				"cookie that outlived its session would otherwise approve. " +
				"Install memorySessionStoresModule (single replica only) or " +
				"redisSessionStoresModule, or leave the grant disabled.",
		);
	}
	return deps.userSessionStore;
};

/**
 * The module's section. The package's `config/reference.conf` holds its
 * defaults. No variable binds a key of it, so the refusal of an old path
 * names none. Parsed whether or not the grant is on, so a setting still
 * written at the old path refuses boot rather than reading as off.
 *
 * `store` is removed, at either path: no value of it declares anything, since
 * the grant needs a store while on and nothing while off. The old path is
 * mapped key by key rather than as a whole: a whole-section entry would send
 * `oauth.deviceAuthorization.store` to `device-grant.store`, a path refused in
 * turn, which boot refuses as a chain.
 */
const SECTION = {
	schema: deviceGrantConfigSchema,
	reference: new URL("../config/reference.conf", import.meta.url),
	relocatedFrom: {
		"oauth.deviceAuthorization.enabled": { to: "enabled", environmentVariable: null },
		"oauth.deviceAuthorization.verification-uri": {
			to: "verificationUri",
			environmentVariable: null,
		},
		"oauth.deviceAuthorization.verification-uri-complete": {
			to: "verificationUriComplete",
			environmentVariable: null,
		},
		"oauth.deviceAuthorization.code-lifetime-seconds": {
			to: "codeLifetimeSeconds",
			environmentVariable: null,
		},
		"oauth.deviceAuthorization.polling-interval-seconds": {
			to: "pollingIntervalSeconds",
			environmentVariable: null,
		},
		"oauth.deviceAuthorization.rateLimit": { to: "rateLimit", environmentVariable: null },
		"oauth.deviceAuthorization.store": null,
		"device-grant.store": null,
	},
	// The module's switch: on only when the section says so.
	isEnabled: (section: z.output<typeof deviceGrantConfigSchema>) => section?.enabled === true,
} as const;

/**
 * The device grant — see the file header for what `device-grant.enabled`
 * decides. List it as it is: it is built from nothing, and reads its switch
 * and its settings from the configuration boot parses.
 */
export const deviceAuthorizationGrantModule = defineModule<
	Requires,
	Optional,
	typeof deviceGrantConfigSchema
>({
	name: "device-grant",
	section: SECTION,
	requires: REQUIRES,
	optional: OPTIONAL,
	// Optional to wire, not optional to decide. A composition with no
	// sink discards every device approval — a consent event — with no
	// symptom, so it has to list `auditSink` in `core.declaredAbsent` to say so.
	absencePolicies: {
		auditSink: AUDIT_SINK_ABSENCE_POLICY,
	},
	contributes: {
		// Both prefixes are claimed with no budget: no limiter decides the
		// verification's limit, which the attempt guard counts at the declared
		// setting, and the device_authorization guard runs on the limiter's own limits.
		rateLimitBudgets: {
			[DEVICE_VERIFICATION_ATTEMPT_TAG]: verifierLimitClaim({ setting: "device-grant.rateLimit" }),
			[DEVICE_AUTHORIZATION_RATE_LIMIT_PREFIX]: () => null,
		},
		// Absent while the grant is off — see the file header — `/oauth/token`
		// answers `unsupported_grant_type` for an unregistered grant, and
		// `grant_types_supported`, read off the same resolver, does not name
		// it: the document and the endpoint say the same thing.
		admissionActions: DEVICE_GRANT_ADMISSION_ACTIONS,
		grants: {
			[DEVICE_CODE_GRANT_TYPE]: (deps) => {
				return createDeviceCodeGrant({
					store: requireDeviceCodeStore(deps),
					keyStore: deps.keyStore,
					accessTokenExpiresIn: tokenSettings(deps).accessTokenLifetime.defaultExpiresIn,
					logger: deps.logger,
					grantPolicy: deps.grantPolicy,
					// An approval a later sessions boundary covers is refused
					// at the poll (see grant.mts).
					...(deps.subjectRevocation ? { subjectRevocation: deps.subjectRevocation } : {}),
				});
			},
		},
		routes: [
			(deps) => {
				const slice = enabledSection(deps.section);
				const router = express.Router();
				// Every middleware on both device routes is a route on `/` — the
				// endpoint's own path — not `router.use`: core mounts this router on
				// its path by prefix, so a `use` mount would run for a later module's
				// `/oauth/device_authorization/custom` too, throttling, parsing and
				// refusing a request that is not this endpoint's. The error handlers
				// stay `router.use`: Express skips routes while an error is pending, and
				// an error here can only come from this router's own layers.
				router.all("/", noStore);
				// With a limiter wired, throttled ahead of client authentication,
				// as at the token endpoint, so unauthenticated hits are bounded
				// before any repository lookup and a public client cannot fill the
				// device-code store; ahead of the size check too, so an oversized
				// request spends an attempt. Keyed `device_authorization:ip:<ip>`.
				// Without one, a declared absence, requests pass through.
				if (deps.rateLimiter !== undefined) {
					router.all(
						"/",
						createRateLimitGuard({
							limiter: deps.rateLimiter,
							tag: DEVICE_AUTHORIZATION_RATE_LIMIT_PREFIX,
							...(deps.logger ? { logger: deps.logger } : {}),
							auditSink: deps.auditSink,
						}),
					);
				}
				// Router-level body parsing, matching `oauthEndpointsModule` and the
				// WebAuthn routes: `createApp` installs no global parser. A
				// declared oversized body is refused before it is read.
				router.all("/", withinBodyLimit);
				router.all("/", express.json({ limit: BODY_LIMIT }));
				router.all("/", express.urlencoded({ extended: false, limit: BODY_LIMIT }));
				router.use(parserRefusals);
				// RFC 8628 §3.1 / §5.6: the client authentication `/oauth/token`
				// uses, with public clients identified by `client_id` alone.
				router.all(
					"/",
					createClientAuthMiddleware(deps.clientRepository, {
						issuer: tokenSettings(deps).issuer,
						allowPublicClients: true,
						// Records a `private_key_jwt` assertion's `jti`; without it
						// such clients get `server_error`. The accepted `aud` is
						// derived from `issuer`, as at `/oauth/revoke`.
						...(deps.replaySeenSet ? { replaySeenSet: deps.replaySeenSet } : {}),
						...(deps.logger ? { logger: deps.logger } : {}),
						fetch: createOutboundFetch({ policy: deps.outboundPolicy, source: "registration" }),
					}),
				);
				router.post(
					"/",
					createDeviceAuthorizationHandler({
						store: requireDeviceCodeStore(deps),
						settings: {
							verificationUri: requireVerificationUri(slice),
							verificationUriComplete: slice.verificationUriComplete,
							codeLifetimeSeconds: slice.codeLifetimeSeconds,
							pollingIntervalSeconds: slice.pollingIntervalSeconds,
						},
						logger: deps.logger,
					}),
				);
				router.use(unexpectedErrors(deps.logger));
				return {
					id: "device-authorization",
					mountPath: "/oauth/device_authorization",
					handler: router,
				};
			},
			(deps) => {
				const slice = enabledSection(deps.section);
				const router = express.Router();
				router.all("/", noStore);
				// JSON only — see the file header. No form parser is mounted, and
				// the handler also refuses other media types itself (415): the
				// rule belongs to the endpoint, not to what is mounted around it.
				router.all("/", withinBodyLimit);
				router.all("/", express.json({ limit: BODY_LIMIT }));
				router.use(parserRefusals);
				// The session module's CSRF guard, on the whole route rather than
				// on `approve` / `deny` alone, so no future action can forget it.
				const csrfMiddleware = requireCsrfMiddleware(deps);
				const userSessionStore = requireUserSessionStore(deps);
				requireSessionLifecycleStore(deps);
				router.post(
					"/",
					csrfMiddleware,
					createDeviceVerificationHandler({
						store: requireDeviceCodeStore(deps),
						// The attempts RFC 8628 §5.1 sizes the user code against,
						// counted per subject on the slot's counter.
						attemptLimit: readVerificationAttemptSpec(slice),
						...(deps.attemptCounter ? { attemptCounter: deps.attemptCounter } : {}),
						deploymentMode: deps.deploymentMode,
						// What session admission reads for every action: the
						// live session, and the requirements registered.
						userSessionStore,
						requirements: deps.sessionRequirementResolver,
						// The deployment's flag, as `/authorize` reads it: from
						// the oauth module's settings.
						requireEmailVerified: tokenSettings(deps).requireEmailVerified,
						// The sessions boundary admission reads, when the
						// composition wires one.
						...(deps.subjectRevocation ? { subjectRevocation: deps.subjectRevocation } : {}),
						sessionLifecycleStore: deps.sessionLifecycleStore,
						settings: {
							verificationUri: requireVerificationUri(slice),
							verificationUriComplete: slice.verificationUriComplete,
							codeLifetimeSeconds: slice.codeLifetimeSeconds,
							pollingIntervalSeconds: slice.pollingIntervalSeconds,
						},
						logger: deps.logger,
						auditSink: deps.auditSink,
					}),
				);
				router.use(unexpectedErrors(deps.logger));
				return {
					id: "device-verification",
					mountPath: "/oauth/device/verification",
					handler: router,
				};
			},
		],
		discoveryMetadata: [
			() => {
				// RFC 8628 §4: a client that cannot discover this endpoint cannot
				// start the flow. An issuer-relative path under `endpoints`, which
				// core prefixes and validates (it refuses `*_endpoint` under
				// `metadata`). The grant type is advertised via the grant
				// resolver, not here.
				return {
					endpoints: { device_authorization_endpoint: "/oauth/device_authorization" },
				};
			},
		],
	},
});
