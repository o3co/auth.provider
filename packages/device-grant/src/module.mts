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
 * Module factory for the RFC 8628 device authorization grant. Enabled, it
 * contributes the `urn:ietf:params:oauth:grant-type:device_code` grant,
 * `POST /oauth/device_authorization` (where a device starts),
 * `POST /oauth/device/verification` (where the user answers),
 * `device_authorization_endpoint` in discovery (RFC 8628 §4), and the three
 * actions verification admits (`DEVICE_GRANT_ADMISSION_ACTIONS`).
 *
 * Off by default. The switch is read from the config handed to
 * `deviceGrantModule({ config })`; disabled, no grant or action is registered
 * (so `grant_types_supported` does not name it), no discovery field is added
 * and both routes answer 404. Routes and discovery use the config `createApp`
 * parsed, and boot is refused if the two disagree (`settingsFor`).
 *
 * Enabled, boot is refused without each setting and slot the grant needs to
 * be safe; the `require*` helpers below say why. The verification endpoint
 * authorises on the session cookie, which makes it a CSRF target (RFC 8628
 * §5.4 remote phishing: a foreign page auto-submits `approve` for the
 * attacker's `user_code`), so it accepts JSON only — a form POST needs no
 * preflight — and runs the session module's `csrfGuard` on the whole route.
 */

import {
	type AppConfig,
	AUDIT_SINK_ABSENCE_POLICY,
	checkOAuthTokenSettings,
	consoleLogger,
	createRateLimitGuard,
	DEVICE_CODE_STORE_ABSENCE_POLICY,
	defineModule,
	guardedRead,
	loggableError,
	MAX_DURATION_SECONDS,
	type Module,
	type ProviderDeps,
	type RateLimitFailMode,
	type RateLimitSpec,
	requireUsableConfiguredRateLimitSpec,
	resolveAccessTokenLifetime,
} from "@o3co/auth-provider-core";
import { createClientAuthMiddleware } from "@o3co/auth-provider-oauth";
import express, { type ErrorRequestHandler, type RequestHandler, type Response } from "express";
import { z } from "zod";
import {
	createDeviceAuthorizationHandler,
	DEVICE_CODE_LIFETIME_SECONDS,
	DEVICE_POLLING_INTERVAL_SECONDS,
} from "./deviceAuthorizationEndpoint.mjs";
import { DEVICE_GRANT_ADMISSION_ACTIONS } from "./admissionActions.mjs";
import { createDeviceCodeGrant } from "./grant.mjs";
import { DEVICE_AUTHORIZATION_RATE_LIMIT_PREFIX, DEVICE_CODE_GRANT_TYPE } from "./types.mjs";
import { createDeviceVerificationHandler } from "./verificationEndpoint.mjs";

/**
 * `oauth.deviceAuthorization.rateLimit` — the budget RFC 8628 §5.1 sizes the
 * user code against. `.int().positive()` is load-bearing: an empty
 * environment variable coerces to `0`, and a zero budget locks every user out.
 */
const rateLimitSpecSchema = z.object({
	limit: z.number().int().positive(),
	// One year at most, as core's schema holds every duration an operator
	// writes: a window past the Date range is one the limiter refuses anyway.
	windowSeconds: z.number().int().positive().max(MAX_DURATION_SECONDS),
});

/** §5.1's worked example: "only allow 5 attempts"; five minutes is half the default code lifetime. */
const DEFAULT_VERIFICATION_RATE_LIMIT = { limit: 5, windowSeconds: 300 } as const;

export const deviceGrantConfigSchema = z.object({
	oauth: z.object({
		deviceAuthorization: z
			.object({
				/**
				 * When false (the default), the module contributes no grant and no
				 * discovery field, and its two routes answer 404.
				 */
				enabled: z.boolean().default(false),
				/**
				 * The page where the end user types the code. No default: the
				 * page belongs to the deployment, and a guessed URL is one the
				 * device would display to users who cannot use it.
				 */
				"verification-uri": z.string().url().optional(),
				/**
				 * Emit `verification_uri_complete` (RFC 8628 §3.3.1). Off by
				 * default — §5.4 warns that removing the typing step removes the
				 * proof that the device is in the user's possession, which is what
				 * makes remote phishing hard.
				 */
				"verification-uri-complete": z.boolean().default(false),
				/**
				 * §5.4: "long enough lifetime to be useable ... but sufficiently
				 * short to limit the usability of a code obtained for phishing".
				 */
				"code-lifetime-seconds": z
					.number()
					.int()
					.min(DEVICE_CODE_LIFETIME_SECONDS.min)
					.max(DEVICE_CODE_LIFETIME_SECONDS.max)
					.default(600),
				/** Advertised as `interval`; also what the store enforces. */
				"polling-interval-seconds": z
					.number()
					.int()
					.min(DEVICE_POLLING_INTERVAL_SECONDS.min)
					.max(DEVICE_POLLING_INTERVAL_SECONDS.max)
					.default(5),
				/**
				 * The verification endpoint's budget per authenticated subject,
				 * seeded into the rate limiter under the `device_verification`
				 * prefix (an adapter's own `limits.device_verification` wins).
				 */
				rateLimit: rateLimitSpecSchema.default(DEFAULT_VERIFICATION_RATE_LIMIT),
				/**
				 * Declared absence for the `deviceCodeStore` slot.
				 * `"unsupported"` is the only value; anything else is a typo that
				 * would otherwise read as a declaration.
				 */
				store: z.literal("unsupported").optional(),
			})
			.default(() => ({
				enabled: false,
				"verification-uri-complete": false,
				"code-lifetime-seconds": 600,
				"polling-interval-seconds": 5,
				rateLimit: DEFAULT_VERIFICATION_RATE_LIMIT,
			})),
	}),
});

interface DeviceAuthorizationConfigSlice {
	readonly enabled: boolean;
	readonly "verification-uri"?: string;
	readonly "verification-uri-complete": boolean;
	readonly "code-lifetime-seconds": number;
	readonly "polling-interval-seconds": number;
	/**
	 * Applied by core's limiter modules when they seed `limits`; here it is
	 * only required to be present and usable.
	 */
	readonly rateLimit?: unknown;
}

const REQUIRES = [
	"config",
	"clientRepository",
	"keyStore",
	// Session admission's synthetic key: the verification endpoint admits
	// each action through it. The planner always fills it.
	"sessionRequirementResolver",
] as const;
// `replaySeenSet` records a client assertion's single-use `jti`. Optional as
// on the OAuth router: without it a `private_key_jwt` request is
// `server_error`, never an assertion accepted unchecked.
const OPTIONAL = [
	"deviceCodeStore",
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
	// The session module's CSRF policy, run on the whole verification route.
	// Required once the grant is enabled (`requireCsrfGuard`).
	"csrfGuard",
	// What the oauth module provides of `oauth {}`: the issuer, the
	// access-token lifetime and `requireEmailVerified`. Optional: another token
	// endpoint may dispatch through core's grant registry, and then they are
	// read from the configuration (`tokenSettings`).
	"oauthTokenSettings",
] as const;

/**
 * The deps every contribution of {@link deviceGrantModule} receives: exactly
 * its `requires` / `optional`, typed.
 */
type Requires = (typeof REQUIRES)[number];
type Optional = (typeof OPTIONAL)[number];
export type DeviceGrantModuleDeps = ProviderDeps<Requires, Optional>;

/**
 * What this module reads of `oauth {}`: the `oauthTokenSettings` slot when a
 * module provides it (checked whole by `checkOAuthTokenSettings`), otherwise
 * the configuration. Each value is resolved only where it is needed.
 */
const tokenSettings = (deps: DeviceGrantModuleDeps) => {
	const held = () =>
		deps.oauthTokenSettings === undefined
			? undefined
			: checkOAuthTokenSettings(deps.oauthTokenSettings, deps.config);
	return {
		issuer: (): string => {
			const settings = held();
			return settings === undefined ? deps.config.oauth.jwt.issuer : settings.issuer;
		},
		accessTokenDefaultExpiresIn: (): number => {
			const settings = held();
			return (
				settings === undefined
					? resolveAccessTokenLifetime(deps.config)
					: settings.accessTokenLifetime
			).defaultExpiresIn;
		},
		requireEmailVerified: (): boolean => {
			const settings = held();
			return settings === undefined
				? deps.config.oauth?.requireEmailVerified === true
				: settings.requireEmailVerified;
		},
	};
};

const readSettings = (deps: DeviceGrantModuleDeps): DeviceAuthorizationConfigSlice | null => {
	const slice = deps.config?.oauth?.deviceAuthorization as
		| DeviceAuthorizationConfigSlice
		| undefined;
	if (slice?.enabled !== true) return null;
	return slice;
};

/**
 * The factory's decision: whether the grant is on in the config the
 * composition root read before boot. `=== true` because that read parses the
 * switch as boot does — core's schema turns an environment-variable `"true"`
 * into a boolean — and anything else is off, which is the secure default.
 */
const isEnabled = (config: AppConfig): boolean =>
	config.oauth?.deviceAuthorization?.enabled === true;

/**
 * The settings slice from the config `createApp` parsed (`null` when the
 * grant is off there), held to the factory's decision. A disagreement refuses
 * boot; otherwise half a grant would run — advertised with no way to start
 * it, or startable while the token endpoint refuses it.
 */
const settingsFor = (
	enabled: boolean,
	deps: DeviceGrantModuleDeps,
): DeviceAuthorizationConfigSlice | null => {
	const slice = readSettings(deps);
	if ((slice !== null) !== enabled) {
		const [built, booted] = enabled ? ["on", "off"] : ["off", "on"];
		throw new Error(
			`deviceGrantModule: built from a configuration with the grant ${built}, but the ` +
				`configuration createApp parsed has oauth.deviceAuthorization.enabled ${booted}. ` +
				"Whether the grant is contributed is decided from the first — the configuration " +
				"read before boot — and its routes and discovery field from the second. " +
				"Read oauth.deviceAuthorization.enabled before boot from the same configuration " +
				"files, parsed as boot parses it — with core's readTransitionalConfig naming the " +
				"path (the standalone template: readSwitches, `reads`) — so that an environment " +
				'variable\'s "true" is on in both.',
		);
	}
	return slice;
};

const requireVerificationUri = (slice: DeviceAuthorizationConfigSlice): string => {
	const uri = slice["verification-uri"];
	if (typeof uri !== "string" || uri === "") {
		throw new Error(
			"deviceGrantModule: oauth.deviceAuthorization.enabled = true requires " +
				"oauth.deviceAuthorization.verification-uri. It is the page this " +
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
 * What a disabled deployment mounts: a 404 whose description names the config
 * key, so an operator can tell a disabled grant from an uninstalled one. It
 * reads nothing else of the config, so a disabled grant's required settings
 * are never checked.
 */
const disabledRoute = (id: string, mountPath: string) => {
	const router = express.Router();
	router.all("/", (_req, res) => {
		// Same cache directives as the live endpoints. A 404 with no
		// directives is exactly the shape an intermediary heuristically
		// caches — and a cached "this deployment has no device grant" would
		// outlive the operator turning it on.
		res
			.status(404)
			.set("Cache-Control", "no-store")
			.set("Pragma", "no-cache")
			.json({
				error: "not_found",
				error_description:
					"the device authorization grant is not enabled on this deployment " +
					"(oauth.deviceAuthorization.enabled = false)",
			});
	});
	return { id, mountPath, handler: router };
};

/**
 * The `csrfGuard` slot the session module provides — the guard
 * `/session/login` runs. Required when the grant is on: the verification
 * endpoint authorises on the session cookie and would otherwise have no CSRF
 * defence.
 */
const requireCsrfGuard = (
	deps: DeviceGrantModuleDeps,
): NonNullable<DeviceGrantModuleDeps["csrfGuard"]> => {
	if (deps.csrfGuard === undefined) {
		throw new Error(
			"deviceGrantModule: oauth.deviceAuthorization.enabled = true requires a " +
				"csrfGuard component. POST /oauth/device/verification runs inside the end-user " +
				"session and is guarded by the same CSRF policy as /session/login — a signed " +
				"double-submit token, and an Origin/Referer check against " +
				"session.csrf.trustedOrigins — which the session module (sessionModule) provides; " +
				"without it the endpoint cannot be mounted safely. Install the session module, " +
				"or leave the grant disabled.",
		);
	}
	return deps.csrfGuard;
};

/**
 * `rateLimit.failMode` is the product's one outage policy for a failed
 * limiter backend; defaulting it here would be a second policy, so its
 * absence refuses boot. Both route factories call this, so the refusal does
 * not depend on planner order.
 */
const requireFailMode = (deps: DeviceGrantModuleDeps): RateLimitFailMode => {
	const failMode = deps.config?.rateLimit?.failMode;
	if (failMode !== "open" && failMode !== "closed") {
		throw new Error(
			"deviceGrantModule: oauth.deviceAuthorization.enabled = true requires " +
				'rateLimit.failMode ("open" | "closed"). POST /oauth/device_authorization ' +
				"and POST /oauth/device/verification both apply the shared rate-limit " +
				"outage policy, and what that policy does when the limiter backend is " +
				"down is the product's decision, not this module's.",
		);
	}
	return failMode;
};

const requireRateLimiter = (
	deps: DeviceGrantModuleDeps,
): NonNullable<DeviceGrantModuleDeps["rateLimiter"]> => {
	if (deps.rateLimiter === undefined) {
		throw new Error(
			"deviceGrantModule: oauth.deviceAuthorization.enabled = true requires a " +
				"rateLimiter component. RFC 8628 §5.1 sizes the user code's entropy " +
				"against a rate limit — 8 base-20 characters is ~34.5 bits, which is " +
				"sufficient only because an attacker gets a handful of attempts. " +
				"Without a limiter that argument does not hold, so this refuses to " +
				"boot rather than serving a code that looks strong and is not.",
		);
	}
	return deps.rateLimiter;
};

/**
 * Presence check for the optional `deviceCodeStore` slot, read by the grant
 * and both endpoints. Declaring the store `"unsupported"` is for deployments
 * that leave the grant off; it does not let an enabled grant run without one.
 */
const requireDeviceCodeStore = (
	deps: DeviceGrantModuleDeps,
): NonNullable<DeviceGrantModuleDeps["deviceCodeStore"]> => {
	if (deps.deviceCodeStore === undefined) {
		throw new Error(
			"deviceGrantModule: oauth.deviceAuthorization.enabled = true requires a " +
				"deviceCodeStore component. The grant has nowhere to record a pending " +
				"authorization, so no device could ever be authorized; declaring the store " +
				'absent (oauth.deviceAuthorization.store = "unsupported") says why it is ' +
				"missing and does not make the grant work without one. Install " +
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
			"deviceGrantModule: oauth.deviceAuthorization.enabled = true requires a " +
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
 * The limiter applies this budget to `device_verification` only because its
 * adapter module seeds that prefix from `oauth.deviceAuthorization.rateLimit`,
 * and it seeds nothing when the key is absent. A hand-built config that
 * skipped the schema default would silently run on the adapter's default
 * budget instead of the one the `rateLimiter` requirement reasons from. An
 * unusable key is refused with the same call the seed makes, so both give the
 * same message.
 */
const requireVerificationRateLimit = (slice: DeviceAuthorizationConfigSlice): RateLimitSpec => {
	const spec = slice.rateLimit;
	if (spec === undefined) {
		throw new Error(
			"deviceGrantModule: oauth.deviceAuthorization.enabled = true requires " +
				"oauth.deviceAuthorization.rateLimit { limit, windowSeconds }. It is the budget " +
				"RFC 8628 §5.1 sizes the user code against and the value the limiter adapter " +
				"seeds `device_verification` from; without it POST /oauth/device/verification " +
				"would run on the adapter's default budget, which is not the number the " +
				"rateLimiter requirement reasons from.",
		);
	}
	return requireUsableConfiguredRateLimitSpec("oauth.deviceAuthorization.rateLimit", spec);
};

/**
 * The `oauth.deviceAuthorization` section: its schema, the package's
 * `config/reference.conf` holding its defaults, and its path. `configSchema`
 * declares the same path with the same schema until the section moves under
 * the module's name, so boot parses the value twice (idempotently).
 */
const DEVICE_GRANT_SECTION_SCHEMA = deviceGrantConfigSchema.shape.oauth.shape.deviceAuthorization;

/**
 * The device grant, built for one config — see the file header for what
 * `oauth.deviceAuthorization.enabled` decides here.
 *
 * Hand it the config the composition root boots with, as `oauthModule({ config })`
 * and `oauthAuthorizationModule({ config })` take theirs.
 */
export const deviceGrantModule = (params: { config: AppConfig }): Module => {
	const enabled = isEnabled(params.config);
	return defineModule<Requires, Optional, typeof DEVICE_GRANT_SECTION_SCHEMA>({
		name: "device-grant",
		configSchema: deviceGrantConfigSchema,
		section: {
			schema: DEVICE_GRANT_SECTION_SCHEMA,
			reference: new URL("../config/reference.conf", import.meta.url),
			at: "oauth.deviceAuthorization",
		},
		requires: REQUIRES,
		optional: OPTIONAL,
		// Optional to wire, not optional to decide. A composition with no
		// sink discards every device approval — a consent event — with no
		// symptom, so it has to write `audit.sink.type = "none"` to say so.
		absencePolicies: {
			deviceCodeStore: DEVICE_CODE_STORE_ABSENCE_POLICY,
			auditSink: AUDIT_SINK_ABSENCE_POLICY,
		},
		contributes: {
			// Only when enabled — see the file header. Absent, `/oauth/token`
			// answers `unsupported_grant_type` for an unregistered grant, and
			// `grant_types_supported`, read off the same resolver, does not name
			// it: the document and the endpoint say the same thing.
			...(enabled
				? {
						admissionActions: DEVICE_GRANT_ADMISSION_ACTIONS,
						grants: {
							[DEVICE_CODE_GRANT_TYPE]: (deps: DeviceGrantModuleDeps) => {
								// Name-keyed contributions run before the routes, so the
								// disagreement check comes first here too — ahead of the
								// store the booted config may rightly say it lacks.
								settingsFor(enabled, deps);
								return createDeviceCodeGrant({
									store: requireDeviceCodeStore(deps),
									keyStore: deps.keyStore,
									accessTokenExpiresIn: tokenSettings(deps).accessTokenDefaultExpiresIn(),
									logger: deps.logger,
									// An approval a later sessions boundary covers is refused
									// at the poll (see grant.mts).
									...(deps.subjectRevocation ? { subjectRevocation: deps.subjectRevocation } : {}),
								});
							},
						},
					}
				: {}),
			routes: [
				(deps: DeviceGrantModuleDeps) => {
					const slice = settingsFor(enabled, deps);
					if (slice === null) {
						return disabledRoute("device-authorization", "/oauth/device_authorization");
					}
					const router = express.Router();
					// Every middleware on both device routes is a route on `/` — the
					// endpoint's own path — not `router.use`: core mounts this router on
					// its path by prefix, so a `use` mount would run for a later module's
					// `/oauth/device_authorization/custom` too, throttling, parsing and
					// refusing a request that is not this endpoint's. The error handlers
					// stay `router.use`: Express skips routes while an error is pending, and
					// an error here can only come from this router's own layers.
					router.all("/", noStore);
					// Throttled ahead of client authentication, as at the token
					// endpoint, so unauthenticated hits are bounded before any
					// repository lookup and a public client cannot fill the
					// device-code store; ahead of the size check too, so an
					// oversized request spends an attempt. Keyed
					// `device_authorization:ip:<ip>`.
					router.all(
						"/",
						createRateLimitGuard({
							limiter: requireRateLimiter(deps),
							tag: DEVICE_AUTHORIZATION_RATE_LIMIT_PREFIX,
							failMode: requireFailMode(deps),
							...(deps.logger ? { logger: deps.logger } : {}),
							auditSink: deps.auditSink,
						}),
					);
					// Router-level body parsing, matching `oauthModule` and the
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
							issuer: tokenSettings(deps).issuer(),
							allowPublicClients: true,
							// Records a `private_key_jwt` assertion's `jti`; without it
							// such clients get `server_error`. The accepted `aud` is
							// derived from `issuer`, as at `/oauth/revoke`.
							...(deps.replaySeenSet ? { replaySeenSet: deps.replaySeenSet } : {}),
							...(deps.logger ? { logger: deps.logger } : {}),
						}),
					);
					router.post(
						"/",
						createDeviceAuthorizationHandler({
							store: requireDeviceCodeStore(deps),
							settings: {
								verificationUri: requireVerificationUri(slice),
								verificationUriComplete: slice["verification-uri-complete"],
								codeLifetimeSeconds: slice["code-lifetime-seconds"],
								pollingIntervalSeconds: slice["polling-interval-seconds"],
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
				(deps: DeviceGrantModuleDeps) => {
					const slice = settingsFor(enabled, deps);
					if (slice === null) {
						return disabledRoute("device-verification", "/oauth/device/verification");
					}
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
					const csrfGuard = requireCsrfGuard(deps);
					// Asserted here so the `rateLimiter` requirement really means the
					// configured budget; the limiter applies it, seeded from config.
					requireVerificationRateLimit(slice);
					const userSessionStore = requireUserSessionStore(deps);
					router.post(
						"/",
						csrfGuard.middleware,
						createDeviceVerificationHandler({
							store: requireDeviceCodeStore(deps),
							rateLimiter: requireRateLimiter(deps),
							// The outage policy the device_authorization guard applies.
							// The handler keys its budget on the subject, so it runs the
							// guard's check itself rather than the guard as middleware.
							failMode: requireFailMode(deps),
							// What session admission reads for every action: the
							// live session, and the requirements registered.
							userSessionStore,
							requirements: deps.sessionRequirementResolver,
							// Read as `/authorize` reads it: `=== true`, so a
							// hand-built config that never passed the schema is off.
							requireEmailVerified: tokenSettings(deps).requireEmailVerified(),
							// The sessions boundary admission reads, when the
							// composition wires one.
							...(deps.subjectRevocation ? { subjectRevocation: deps.subjectRevocation } : {}),
							settings: {
								verificationUri: requireVerificationUri(slice),
								verificationUriComplete: slice["verification-uri-complete"],
								codeLifetimeSeconds: slice["code-lifetime-seconds"],
								pollingIntervalSeconds: slice["polling-interval-seconds"],
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
				(deps: DeviceGrantModuleDeps) => {
					const slice = settingsFor(enabled, deps);
					if (slice === null) return {};
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
};
