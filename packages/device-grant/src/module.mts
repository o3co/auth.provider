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
 * Module factory for the RFC 8628 device authorization grant (#298).
 *
 * Enabled, the module contributes:
 *
 *   - the `urn:ietf:params:oauth:grant-type:device_code` grant on `/token`;
 *   - `POST /oauth/device_authorization`, where a device starts;
 *   - `POST /oauth/device/verification`, where a human answers;
 *   - `device_authorization_endpoint` in the discovery document, because a
 *     client has no other way to find the first of those (RFC 8628 §4).
 *
 * ### Secure-default opt-in
 *
 * `oauth.deviceAuthorization.enabled = false` in `reference.conf`. Mounting a
 * package must not turn on a grant; the operator says so.
 *
 * `deviceGrantModule({ config })` reads that key from the config the
 * composition root hands it, the way `oauthAuthorizationModule` reads
 * `oauth.grants.<name>.enabled`: a grant is contributed only when it is on.
 * A module whose manifest is fixed would have to contribute the grant either
 * way, and oauth's `grant_types_supported` is read off the grant resolver, so
 * a disabled grant registered as a handler that refuses was advertised to
 * every client as supported. Disabled, the module contributes no grant — the
 * token endpoint answers `unsupported_grant_type` as it does for any grant
 * nobody registered — no discovery field, and the two routes answer `404`.
 * The grant, the routes and the discovery field are built from the config
 * `createApp` validated, and a boot where that config disagrees with the
 * factory's is refused (`settingsFor`), first of anything each of them
 * checks, so the two cannot split one grant in half.
 *
 * ### Two settings with no defaults
 *
 * `verification-uri` has none because there is nothing to guess — the page
 * belongs to the deployment, and a device that displays a wrong URL sends
 * users somewhere that cannot help them. A `rateLimiter` is *required* rather
 * than optional for a different reason: RFC 8628 §5.1 computes the user
 * code's entropy budget *against* a rate limit, so an unlimited deployment is
 * not a slower version of a limited one, it is 34.5 bits against an unbounded
 * attacker. Both fail at boot rather than at the first request. So does an
 * enabled grant with no `deviceCodeStore` (#626): the slot is optional to
 * wire, because the #363 absence policy lets a deployment that leaves the
 * grant off boot without one, and declaring it absent says why it is missing
 * — it does not make the grant work without it.
 *
 * ### The verification endpoint is a CSRF target, and is guarded as one
 *
 * `POST /oauth/device/verification` authorises on the end-user session cookie
 * — the one credential a browser attaches to a request some other site made.
 * That is the whole of RFC 8628 §5.4's remote-phishing attack: any public
 * `client_id` obtains a `user_code`, a page on the attacker's origin
 * auto-submits `action=approve&user_code=…` from the victim's browser, and
 * the attacker's device collects the victim's token. Turning
 * `verification_uri_complete` off keeps the *user* typing the code; a forged
 * POST types it for them.
 *
 * So the route the module mounts is JSON-only — a form body is a "simple"
 * request the browser sends without a preflight, `application/json` is not;
 * the handler refuses any other media type itself — and sits behind the
 * same `createCsrfGuard` `/session/login` runs (#272):
 * a foreign `Origin` / `Referer` is refused outright, the server's own origin
 * or one on `session.csrf.trustedOrigins` is accepted, and a request with no
 * origin signal must carry the session's signed double-submit token. That is
 * one CSRF policy for the product rather than a second one that can drift,
 * which is why this package depends on `@o3co/auth-provider-session` rather
 * than restating an origin check. The guard is built from the `session.*`
 * config slice, so enabling the grant without one fails at boot.
 *
 * ### Each route parses its own body
 *
 * Both routes live under `/oauth`, beside `oauthModule`'s router, which
 * parses the bodies of its own routes only. So what these routes accept —
 * the 16 KiB bound, the media type, where a CSRF token may come from — is
 * decided by their own middleware whatever order the modules are listed
 * in, and they declare no ordering edge.
 *
 * ### One outage policy for both routes (#457)
 *
 * Both routes are rate-limited, and both apply `rateLimit.failMode` when the
 * limiter backend itself is down — `POST /oauth/device_authorization` through
 * `createRateLimitGuard`, `POST /oauth/device/verification` through the same
 * check the guard is built on (`checkWithFailMode`, because its budget is
 * keyed on the subject and its 429 is its own audit event). The key is read
 * by `requireFailMode` for each route factory, so a composition that enables
 * the grant with no policy is refused whichever factory the planner runs
 * first. Before #457 only the authorization route read it, and a limiter
 * outage on the verification route was an unhandled throw.
 */

import {
	type AppConfig,
	AUDIT_SINK_ABSENCE_POLICY,
	consoleLogger,
	createRateLimitGuard,
	DEVICE_CODE_STORE_ABSENCE_POLICY,
	defineModule,
	isDeviceVerificationRateLimitSpec,
	type Module,
	type ProviderDeps,
	type RateLimitFailMode,
	type RateLimitSpec,
	resolveAccessTokenLifetime,
} from "@o3co/auth-provider-core";
import { createClientAuthMiddleware } from "@o3co/auth-provider-oauth";
import {
	createCsrfGuard,
	createCsrfProtectionFromConfig,
	type SessionCsrfConfigSlice,
} from "@o3co/auth-provider-session";
import express, { type ErrorRequestHandler, type RequestHandler, type Response } from "express";
import { z } from "zod";
import { createDeviceAuthorizationHandler } from "./deviceAuthorizationEndpoint.mjs";
import { createDeviceCodeGrant } from "./grant.mjs";
import { guardedRead, loggableError } from "./loggableError.mjs";
import { DEVICE_AUTHORIZATION_RATE_LIMIT_PREFIX, DEVICE_CODE_GRANT_TYPE } from "./types.mjs";
import { createDeviceVerificationHandler } from "./verificationEndpoint.mjs";

/**
 * `oauth.deviceAuthorization.rateLimit` — the budget RFC 8628 §5.1 sizes the
 * user code against. `.int().positive()` is load-bearing: `0` is what an
 * empty environment variable coerces to, and a zero-attempt budget locks
 * every user out while a zero window is not a window. Core's
 * `isDeviceVerificationRateLimitSpec` states the same bounds structurally
 * for configs that never passed this schema; the limiter-module seed and
 * `requireVerificationRateLimit` below both read that one definition (#448).
 */
const rateLimitSpecSchema = z.object({
	limit: z.number().int().positive(),
	windowSeconds: z.number().int().positive(),
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
				"code-lifetime-seconds": z.number().int().min(30).max(3600).default(600),
				/** Advertised as `interval`; also what the store enforces. */
				"polling-interval-seconds": z.number().int().min(1).max(60).default(5),
				/**
				 * The verification endpoint's budget per authenticated subject,
				 * seeded into whichever rate-limiter adapter is wired under the
				 * `device_verification` prefix (an operator-declared
				 * `limits.device_verification` on the adapter still wins). This
				 * is the number the "requires a rateLimiter" boot refusal
				 * reasons from, so it has to be the number the limiter applies.
				 */
				rateLimit: rateLimitSpecSchema.default(DEFAULT_VERIFICATION_RATE_LIMIT),
				/**
				 * Declared absence for the `deviceCodeStore` slot (#363).
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
	 * Applied by core's limiter modules when they seed `limits`, not here;
	 * here it is only required to be present and usable (#448).
	 */
	readonly rateLimit?: unknown;
}

const REQUIRES = ["config", "clientRepository", "keyStore"] as const;
// #484: `replaySeenSet` is what records a client assertion's single-use
// `jti`. Optional here for the same reason it is optional on the OAuth
// router — a composition with no `private_key_jwt` client needs none —
// and a request using the method without one is `server_error`, never an
// assertion accepted unchecked.
const OPTIONAL = [
	"deviceCodeStore",
	"rateLimiter",
	"replaySeenSet",
	"logger",
	"auditSink",
] as const;

/**
 * The deps every contribution of {@link deviceGrantModule} receives: exactly
 * its `requires` / `optional`, typed (#626 P2). The helpers below read the
 * optional slots behind a presence check or not at all.
 */
type Requires = (typeof REQUIRES)[number];
type Optional = (typeof OPTIONAL)[number];
export type DeviceGrantModuleDeps = ProviderDeps<Requires, Optional>;

const readSettings = (deps: DeviceGrantModuleDeps): DeviceAuthorizationConfigSlice | null => {
	const slice = deps.config?.oauth?.deviceAuthorization as
		| DeviceAuthorizationConfigSlice
		| undefined;
	if (slice?.enabled !== true) return null;
	return slice;
};

/**
 * The factory's decision: whether the grant is on in the config the
 * composition root holds. `=== true` because `AppConfig` is the parsed shape —
 * core's schema has already turned an environment-variable `"true"` into a
 * boolean — and anything else is off, which is the secure default.
 */
const isEnabled = (config: AppConfig): boolean =>
	config.oauth?.deviceAuthorization?.enabled === true;

/**
 * The settings slice from the config the boot validated — `null` when the
 * grant is off there — held to the factory's own decision.
 *
 * Whether the grant is contributed is decided from the config handed to
 * `deviceGrantModule({ config })`; the routes and the discovery field are
 * built from the one `createApp` validated. A composition root that hands
 * the two different configs would otherwise boot half a grant: one that is
 * registered and advertised while no device can start it, or a flow whose
 * token endpoint refuses the grant. The two are one config in every
 * composition root that follows the pattern, so a disagreement is refused.
 */
const settingsFor = (
	enabled: boolean,
	deps: DeviceGrantModuleDeps,
): DeviceAuthorizationConfigSlice | null => {
	const slice = readSettings(deps);
	if ((slice !== null) !== enabled) {
		const [built, booted] = enabled ? ["on", "off"] : ["off", "on"];
		throw new Error(
			`deviceGrantModule: built from a config with the grant ${built}, but the config ` +
				`createApp validated has oauth.deviceAuthorization.enabled ${booted}. Whether the ` +
				"grant is contributed is decided from the first, its routes and discovery field " +
				"from the second — hand deviceGrantModule({ config }) the same config as " +
				"bootstrapComponents.config.",
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
 * The cache directives every exit of both routes carries — mounted first on
 * each router, so the answers no handler here writes (the throttle's `429`,
 * client authentication's `401`, the CSRF guard's `403`) carry them too, as
 * federation-grants' `transport()` does for its routes. A refusal an
 * intermediary caches is served to the next caller.
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
 * The body limit, restated ahead of the parsers — federation-grants'
 * `withinBodyLimit`, with its status and body.
 *
 * A declared `Content-Length` over the bound is refused here, before any of
 * the body is read. A body with no `Content-Length` (chunked) is left to the
 * parsers' own `limit`, as federation-grants leaves it; no other module's
 * parser reads these routes' bodies (`oauthModule`'s router parses its own
 * routes only), and `parserRefusals` gives the parsers' refusal the same
 * answer.
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
 * A body-parser refusal that is the caller's mistake, as the answer it gets.
 *
 * body-parser raises `http-errors`: `expose: true` with a 4xx `status` for
 * everything the request got wrong — a body over the limit or with more
 * parameters than it takes, a charset or `Content-Encoding` it cannot
 * decode, JSON it cannot read, a compressed body that does not decompress.
 * Those are answered as 4xx, with no error-level log: on the verification
 * route the parser runs ahead of the CSRF guard and of any throttle, so a
 * 500 and an error line for them would let anyone fill the error log at
 * will. `null` for anything else — including an error one of whose three
 * fields throws when read (a getter, a Proxy's trap). The reads go through
 * `guardedRead`: a throw here would be `parserRefusals` throwing, and
 * Express would hand `unexpectedErrors` that throw in place of the error.
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
 * The parsers' refusals, answered — mounted directly after `noStore`, the
 * throttle, `withinBodyLimit` and the parsers, so it sees their errors and
 * nobody else's. What `callerMistake` recognises is the caller's mistake:
 * `413 body_too_large` (a chunked body the parsers found over the bound gets
 * the answer a declared one gets from `withinBodyLimit`), `415
 * unsupported_encoding` or `400 malformed_body`, quoting none of the body
 * and logging nothing at error level. Anything else passes on to
 * `unexpectedErrors`.
 *
 * Mounted last instead, it would read an `expose`d 4xx from anywhere — a
 * store, a handler — as a refused body, and answer and log it as one.
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
 * The last error handler on either route: every error that reaches it is a
 * `500 server_error` (`unexpected_error`), with `loggableError`'s projection
 * of it in the log. RFC 8628 §3.2 gives `/oauth/device_authorization` RFC
 * 6749 §5.2's JSON error response, and the verification API answers in JSON
 * throughout, so nothing falls through to the host app's error page.
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
 * What a disabled deployment mounts instead of the real endpoint.
 *
 * A router that answers 404: to a client the endpoint does not exist, which
 * is exactly what `enabled = false` means. It is mounted rather than left
 * out because, unlike a missing package, the description names the config
 * key, so an operator can tell a disabled grant from an uninstalled one.
 * Nothing here reads the rest of the config, so a deployment that leaves the
 * grant off never trips its required settings.
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
 * The `session.*` slice the verification route's CSRF guard is built from.
 *
 * Checked structurally rather than declared in `configSchema`: the slice is
 * the session module's to validate, and every deployment that can reach this
 * endpoint mounts that module — `req.session.isAuthenticated` is its field.
 * What is refused here is the composition that enables the grant with no
 * session at all, where the guard would have no signing key and no cookie
 * name and the endpoint would be mounted with no CSRF defence.
 */
const SAME_SITE_VALUES: ReadonlySet<unknown> = new Set(["lax", "strict", "none"]);

const requireSessionSlice = (deps: DeviceGrantModuleDeps): SessionCsrfConfigSlice => {
	const session = deps.config?.session as Partial<SessionCsrfConfigSlice> | undefined;
	// Every field `createCsrfProtectionFromConfig` reads is checked here, not
	// just the secret: a slice with no `name` would mint a cookie called
	// `undefined.csrf`, and one with no `secure`/`sameSite` would set cookie
	// attributes the operator never chose. Refuse the whole slice instead.
	const missing: string[] = [];
	if (typeof session?.secret !== "string" || session.secret === "") missing.push("session.secret");
	if (typeof session?.name !== "string" || session.name === "") missing.push("session.name");
	if (typeof session?.secure !== "boolean") missing.push("session.secure");
	if (!SAME_SITE_VALUES.has(session?.sameSite)) missing.push("session.sameSite");
	if (missing.length > 0) {
		throw new Error(
			"deviceGrantModule: oauth.deviceAuthorization.enabled = true requires the " +
				`\`session\` config slice; missing or invalid: ${missing.join(", ")}. ` +
				"POST /oauth/device/verification runs inside the end-user session and is " +
				"guarded by the same CSRF policy as /session/login — a signed double-submit " +
				"token derived from session.secret, a cookie named from session.name with " +
				"session.secure / session.sameSite, and an Origin/Referer check against " +
				"session.csrf.trustedOrigins — so without the slice the guard cannot be built " +
				"and the endpoint cannot be mounted safely.",
		);
	}
	return session as SessionCsrfConfigSlice;
};

/**
 * OR-5: the outage policy for a limiter-backend failure is `rateLimit.failMode`
 * — one decision for the product, read by every guarded route. Defaulting it
 * here would be a second policy, so its absence is a boot refusal. Both
 * route factories call this (#457), so the refusal does not depend on which
 * one the planner happens to run first.
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
 * The store is read by the grant and by both endpoints, and the slot is
 * optional — so this is the presence check, a boot refusal in the same shape
 * as the limiter's (#626). Before it, an enabled grant with the store declared
 * absent (`oauth.deviceAuthorization.store = "unsupported"`) booted and
 * mounted endpoints that threw on the first request; the declaration is for a
 * deployment that leaves the grant off (#363), not a way to run it without
 * one. An enabled grant with no store and no declaration is still refused
 * earlier, by the absence policy, naming the config key.
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
 * #448: the budget the refusal above reasons from has to be one the limiter
 * was actually seeded with.
 *
 * The limiter applies five attempts to `device_verification:` only because
 * its adapter module seeded that prefix from
 * `oauth.deviceAuthorization.rateLimit`, and the seed leaves the adapter's
 * 60/60s default in place — deliberately — when the key is missing or
 * unusable. A composition booted through `createApp` cannot reach here
 * without the key, because the schema defaults it; a hand-built config never
 * passed the schema, and its verification endpoint ran on twelve times the
 * budget the `rateLimiter` requirement argues from, with no symptom. The
 * check is the seed's own predicate, so what this refuses and what the seed
 * declines to apply are the same set of inputs.
 */
const requireVerificationRateLimit = (slice: DeviceAuthorizationConfigSlice): RateLimitSpec => {
	const spec = slice.rateLimit;
	if (!isDeviceVerificationRateLimitSpec(spec)) {
		throw new Error(
			"deviceGrantModule: oauth.deviceAuthorization.enabled = true requires " +
				"oauth.deviceAuthorization.rateLimit { limit, windowSeconds } as positive " +
				"integers. It is the budget RFC 8628 §5.1 sizes the user code against and " +
				"the value the limiter adapter seeds `device_verification` from; without " +
				"it POST /oauth/device/verification would run on the adapter's default " +
				"budget, which is not the number the rateLimiter requirement reasons from.",
		);
	}
	return spec;
};

/**
 * The device grant, built for one config — see the file header for what
 * `oauth.deviceAuthorization.enabled` decides here.
 *
 * Hand it the config the composition root boots with, as `oauthModule({ config })`
 * and `oauthAuthorizationModule({ config })` take theirs.
 */
export const deviceGrantModule = (params: { config: AppConfig }): Module => {
	const enabled = isEnabled(params.config);
	return defineModule<Requires, Optional>({
		name: "device-grant",
		configSchema: deviceGrantConfigSchema,
		requires: REQUIRES,
		optional: OPTIONAL,
		// #363: optional to wire, not optional to decide. A composition with no
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
						grants: {
							[DEVICE_CODE_GRANT_TYPE]: (deps: DeviceGrantModuleDeps) => {
								// Name-keyed contributions run before the routes, so the
								// disagreement check comes first here too — ahead of the
								// store the booted config may rightly say it lacks.
								settingsFor(enabled, deps);
								return createDeviceCodeGrant({
									store: requireDeviceCodeStore(deps),
									keyStore: deps.keyStore,
									accessTokenExpiresIn: resolveAccessTokenLifetime(deps.config).defaultExpiresIn,
									logger: deps.logger,
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
					// Throttled like every other public entry point (#325), and
					// AHEAD of client authentication — the token endpoint's D-6
					// ordering — so repeated unauthenticated hits are bounded before
					// they reach a repository lookup, and so a public client cannot
					// fill the device-code store by asking. Keyed
					// `device_authorization:ip:<ip>`; the adapter resolves the spec
					// by that prefix and falls back to its default. Ahead of the
					// size check too, as federation-grants places it: an oversized
					// request spends an attempt like any other.
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
					// RFC 8628 §3.1 applies RFC 6749 §3.2.1's client-authentication
					// requirements to this endpoint, and §5.6 expects device clients
					// to be public. `allowPublicClients: true` is exactly that pair:
					// a public client is identified by `client_id`, a confidential
					// one must still present its secret. The same middleware and the
					// same option `/oauth/token` uses, so there is one notion of
					// client authentication rather than two that can drift.
					router.all(
						"/",
						createClientAuthMiddleware(deps.clientRepository, {
							issuer: deps.config.oauth.jwt.issuer,
							allowPublicClients: true,
							// #484: the composition's replay store, so a `private_key_jwt`
							// client is authenticated here the way it is at every other
							// endpoint. Without it the middleware has nowhere to record the
							// assertion's `jti` and answers `server_error` — which is what
							// this route did for every such client. The accepted `aud` is
							// derived from `issuer` above, as it is at `/oauth/revoke`.
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
					// JSON only, deliberately — see the file header. A form body is
					// a "simple" request a browser sends cross-site with the
					// victim's cookie and no preflight; JSON is not. No form parser
					// is mounted here, and `oauthModule`'s router parses its own
					// routes only, so nothing else parses this body either. The
					// handler still checks the media type itself and answers
					// anything else `415`: the rule belongs to the endpoint, not to
					// what is mounted around it.
					router.all("/", withinBodyLimit);
					router.all("/", express.json({ limit: BODY_LIMIT }));
					router.use(parserRefusals);
					// The session guard, verbatim: foreign origin refused, same
					// origin or `session.csrf.trustedOrigins` accepted, no origin
					// signal → the signed double-submit token `GET /session/csrf`
					// mints. On the whole route rather than on `approve` / `deny`
					// alone, for the reason the three actions are one route: no
					// way to add a fourth that forgets it.
					const sessionSlice = requireSessionSlice(deps);
					// The budget this route is limited by is applied inside the
					// limiter, seeded from config; asserting it here is what makes
					// the `rateLimiter` requirement mean five attempts (#448).
					requireVerificationRateLimit(slice);
					router.post(
						"/",
						createCsrfGuard({
							csrf: createCsrfProtectionFromConfig(sessionSlice),
							trustedOrigins: sessionSlice.csrf?.trustedOrigins ?? [],
							...(deps.logger ? { logger: deps.logger } : {}),
						}),
						createDeviceVerificationHandler({
							store: requireDeviceCodeStore(deps),
							rateLimiter: requireRateLimiter(deps),
							// The same outage policy the device_authorization guard
							// applies, from the same key (#457): the handler keys
							// its budget on the subject, so it runs the guard's
							// check itself rather than the guard as a middleware.
							failMode: requireFailMode(deps),
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
					// RFC 8628 §4. A client that cannot discover this endpoint cannot
					// start the flow, so the metadata is the feature being reachable
					// rather than a description of it.
					//
					// An issuer-relative path under `endpoints`, which core prefixes
					// with the issuer and validates. Core's builder refuses an
					// `*_endpoint` field under `metadata`, so a URL built here would
					// fail every boot that has an issuer — every boot beside
					// `oauthModule`. The grant type itself is not contributed here:
					// `grant_types_supported` is read off the grant resolver
					// `/oauth/token` dispatches against (#283).
					return {
						endpoints: { device_authorization_endpoint: "/oauth/device_authorization" },
					};
				},
			],
		},
	});
};
