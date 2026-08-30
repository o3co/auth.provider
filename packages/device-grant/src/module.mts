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
 * Module manifest for the RFC 8628 device authorization grant (#298).
 *
 * Contributes three things and requires two:
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
 * ### Two settings with no defaults
 *
 * `verification-uri` has none because there is nothing to guess — the page
 * belongs to the deployment, and a device that displays a wrong URL sends
 * users somewhere that cannot help them. A `rateLimiter` is *required* rather
 * than optional for a different reason: RFC 8628 §5.1 computes the user
 * code's entropy budget *against* a rate limit, so an unlimited deployment is
 * not a slower version of a limited one, it is 34.5 bits against an unbounded
 * attacker. Both fail at boot rather than at the first request.
 */

import { DEVICE_CODE_STORE_ABSENCE_POLICY, defineModule } from "@o3co/auth-provider-core";
import express from "express";
import { z } from "zod";
import { createDeviceAuthorizationHandler } from "./deviceAuthorizationEndpoint.mjs";
import { createDeviceCodeGrant } from "./grant.mjs";
import { DEVICE_CODE_GRANT_TYPE } from "./types.mjs";
import { createDeviceVerificationHandler } from "./verificationEndpoint.mjs";

export const deviceGrantConfigSchema = z.object({
	oauth: z.object({
		deviceAuthorization: z
			.object({
				/** When false (the default), this module contributes nothing. */
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
			})),
	}),
});

interface DeviceAuthorizationConfigSlice {
	readonly enabled: boolean;
	readonly "verification-uri"?: string;
	readonly "verification-uri-complete": boolean;
	readonly "code-lifetime-seconds": number;
	readonly "polling-interval-seconds": number;
}

// biome-ignore lint/suspicious/noExplicitAny: planner-inferred deps shape — the manifest reads only slots it declares in `requires` / `optional`
type AnyDeps = any;

const readSettings = (deps: AnyDeps): DeviceAuthorizationConfigSlice | null => {
	const slice = deps.config?.oauth?.deviceAuthorization as
		| DeviceAuthorizationConfigSlice
		| undefined;
	if (slice?.enabled !== true) return null;
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

/**
 * What a disabled deployment mounts instead of the real endpoint.
 *
 * The `routes` contribution kind has no "skip me" return — a factory produces
 * a route or throws — so a config-disabled module cannot simply omit one. A
 * router that answers 404 is the honest equivalent: from a client's side it
 * is indistinguishable from the package not being installed, which is exactly
 * what `enabled = false` means. Nothing here reads the rest of the config, so
 * a deployment that leaves the grant off never trips its required settings.
 */
const disabledRoute = (id: string, mountPath: string) => {
	const router = express.Router();
	router.all("/", (_req, res) => {
		res.status(404).json({
			error: "not_found",
			error_description:
				"the device authorization grant is not enabled on this deployment " +
				"(oauth.deviceAuthorization.enabled = false)",
		});
	});
	return { id, mountPath, handler: router };
};

const requireRateLimiter = (deps: AnyDeps): NonNullable<AnyDeps["rateLimiter"]> => {
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

export const deviceGrantModule = defineModule({
	name: "device-grant",
	configSchema: deviceGrantConfigSchema,
	requires: ["config", "clientRepository", "keyStore"],
	optional: ["deviceCodeStore", "rateLimiter", "logger"],
	absencePolicies: {
		deviceCodeStore: DEVICE_CODE_STORE_ABSENCE_POLICY,
	},
	contributes: {
		grants: {
			[DEVICE_CODE_GRANT_TYPE]: (deps: AnyDeps) => {
				const slice = readSettings(deps);
				if (slice === null) {
					// Disabled: contribute a handler that refuses, rather than
					// omitting the key. `unsupported_grant_type` is what the token
					// endpoint answers for an unregistered grant anyway, so the
					// observable behaviour matches "not installed".
					return {
						async handle() {
							return {
								result: {
									status: 400,
									error: "unsupported_grant_type",
									errorDescription: "the device authorization grant is not enabled",
								},
							};
						},
					};
				}
				return createDeviceCodeGrant({
					store: deps.deviceCodeStore,
					keyStore: deps.keyStore,
					accessTokenExpiresIn: deps.config.oauth.accessToken.expiresIn,
					logger: deps.logger,
				});
			},
		},
		routes: [
			(deps: AnyDeps) => {
				const slice = readSettings(deps);
				if (slice === null) {
					return disabledRoute("device-authorization", "/oauth/device_authorization");
				}
				const router = express.Router();
				// Router-level body parsing, matching `oauthModule` and the
				// WebAuthn routes: `createApp` installs no global parser.
				router.use(express.json({ limit: "16kb" }));
				router.use(express.urlencoded({ extended: false, limit: "16kb" }));
				router.post(
					"/",
					createDeviceAuthorizationHandler({
						store: deps.deviceCodeStore,
						clientRepository: deps.clientRepository,
						issuerOrigin: deps.config.oauth.jwt.issuer,
						settings: {
							verificationUri: requireVerificationUri(slice),
							verificationUriComplete: slice["verification-uri-complete"],
							codeLifetimeSeconds: slice["code-lifetime-seconds"],
							pollingIntervalSeconds: slice["polling-interval-seconds"],
						},
						logger: deps.logger,
					}),
				);
				return {
					id: "device-authorization",
					mountPath: "/oauth/device_authorization",
					handler: router,
				};
			},
			(deps: AnyDeps) => {
				const slice = readSettings(deps);
				if (slice === null) {
					return disabledRoute("device-verification", "/oauth/device/verification");
				}
				const router = express.Router();
				router.use(express.json({ limit: "16kb" }));
				router.use(express.urlencoded({ extended: false, limit: "16kb" }));
				router.post(
					"/",
					createDeviceVerificationHandler({
						store: deps.deviceCodeStore,
						rateLimiter: requireRateLimiter(deps),
						settings: {
							verificationUri: requireVerificationUri(slice),
							verificationUriComplete: slice["verification-uri-complete"],
							codeLifetimeSeconds: slice["code-lifetime-seconds"],
							pollingIntervalSeconds: slice["polling-interval-seconds"],
						},
						logger: deps.logger,
					}),
				);
				return {
					id: "device-verification",
					mountPath: "/oauth/device/verification",
					handler: router,
				};
			},
		],
		discoveryMetadata: [
			(deps: AnyDeps) => {
				const slice = readSettings(deps);
				if (slice === null) return {};
				// RFC 8628 §4. A client that cannot discover this endpoint cannot
				// start the flow, so the metadata is the feature being reachable
				// rather than a description of it.
				const issuer = deps.config.oauth.jwt.issuer as string;
				return {
					metadata: {
						device_authorization_endpoint: new URL(
							"/oauth/device_authorization",
							issuer,
						).toString(),
					},
					// The grant appears in `grant_types_supported` through the same
					// aggregation every other grant uses (#283).
					grantTypes: [DEVICE_CODE_GRANT_TYPE],
				};
			},
		],
	},
});
