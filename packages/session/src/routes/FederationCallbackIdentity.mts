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
 * Who the callback's user is: the authorization code exchanged with the
 * upstream IdP for its profile, the local account that profile's identity
 * resolves to, if any, and the lifetime its access token is recorded with.
 * Runs only on a state the callback retired.
 *
 * The lifetime is read once, through core's reading at a floor of 0 with no
 * cap. Finite with `expiresIn` stated: `obtainedAt` is the instant before the
 * exchange and `expiresAt` the reading's end. Otherwise: the adapter's
 * `expiresAt` and no `obtainedAt`. A lifetime that cannot be read is a failed
 * exchange (502).
 */

import {
	type FederationProvider,
	type FederationTokens,
	type Logger,
	loggableError,
	readUpstreamTokenLifetime,
	sanitizeErrorText,
	type UserRepository,
} from "@o3co/auth-provider-core";
import type { Response } from "express";
import { USER_DIRECTORY_UNAVAILABLE } from "../internal/cookieSession.mjs";
import type { FederationRouterContext } from "./FederationContext.mjs";
import { logMisconfigured, logStoreUnavailable } from "./FederationLog.mjs";

/** The lifetime fields a link-time `FederationTokens` record carries. */
export type LinkedTokenLifetime = Pick<FederationTokens, "expiresAt" | "obtainedAt">;

/**
 * The upstream's profile, the identity token it names, the local account it
 * resolves to (`null` for none), and the lifetime its access token is
 * recorded with.
 */
export interface FederatedIdentity {
	readonly profile: Awaited<ReturnType<FederationProvider["exchangeCode"]>>;
	readonly identityToken: string;
	readonly user: Awaited<ReturnType<UserRepository["authenticateByToken"]>>;
	readonly lifetime: LinkedTokenLifetime;
}

/**
 * The lifetime a code exchange's answer gives the record, through core's
 * reading with a floor of 0 and no cap. Finite with `expiresIn` stated: the
 * reading's end, and `obtainedAt` = `calledAt`. Any other reading (an end
 * stated only as an instant, which is on the upstream's clock; none;
 * malformed; contradictory; spent): the adapter's `expiresAt` as stated,
 * `null` included, and no `obtainedAt`, which fails closed. Throws only
 * where reading the answer's fields throws.
 */
const readLinkedLifetime = (
	profile: Awaited<ReturnType<FederationProvider["exchangeCode"]>>,
	calledAt: number,
): LinkedTokenLifetime => {
	const { expiresIn, expiresAt } = profile;
	const reading = readUpstreamTokenLifetime(
		{ expiresIn, expiresAt },
		{ calledAt, now: Date.now(), floorMs: 0 },
	);
	if (reading.verdict === "finite" && reading.stated !== "expiresAt") {
		return { expiresAt: reading.expiresAt, obtainedAt: reading.obtainedAt };
	}
	return { expiresAt };
};

/**
 * Exchange the callback's code and resolve the identity. Answers and returns
 * `null` on a refusal, an upstream failure or an outage.
 */
export const identifyFederatedUser = async (
	ctx: FederationRouterContext,
	provider: FederationProvider,
	params: Readonly<Record<string, string>>,
	codeVerifier: string,
	nonce: string | undefined,
	res: Response,
	log: Logger,
): Promise<FederatedIdentity | null> => {
	const { providerCallbackUrls, userRepository } = ctx;

	// A missing or empty `code` is a 400, not an empty string sent to the IdP
	// (which would surface as a 502).
	const codeParam = params.code;
	if (typeof codeParam !== "string" || codeParam.length === 0) {
		res.status(400).json({
			error: "invalid_request",
			error_description: "Missing authorization code",
		});
		return null;
	}

	// Exchange the authorization code for a FederationProfile
	// providerCallbackUrls is the authoritative map; the same entry the start
	// verified (`FederationStart.mts`).
	const callbackUrl = providerCallbackUrls.get(provider.name);
	if (!callbackUrl) {
		logMisconfigured(log, "no_callback_url");
		res.status(500).json({
			error: "misconfiguration",
			error_description: sanitizeErrorText(
				`No callback URL registered for provider '${provider.name}'`,
			),
		});
		return null;
	}

	// What the adapter sees of the callback, minus `code` (passed in its own
	// field) and `state` (already checked, `FederationCallbackState.mts`): a
	// generic bag carrying them would be a second, unchecked place to read a
	// credential from.
	const { code: _code, state: _state, ...adapterCallbackParams } = params;

	let profile: Awaited<ReturnType<FederationProvider["exchangeCode"]>>;
	let lifetime: LinkedTokenLifetime;
	// An `expiresIn` counts from before the exchange: time the upstream took is not life left.
	const calledAt = Date.now();
	try {
		profile = await provider.exchangeCode({
			code: codeParam,
			codeVerifier,
			redirectUri: callbackUrl,
			// The session-stored nonce, so OIDC adapters bind the id_token via
			// `expectedNonce`; OAuth-only adapters ignore it.
			nonce,
			// The remaining callback parameters, so an adapter can read identity
			// an IdP delivers beside the token response (Apple's first-login
			// `user` body — unsigned, so `mapClaims` and claim precedence decide
			// what it may affect) or RFC 9207's `iss`.
			callbackParams: adapterCallbackParams,
		});
		// An answer whose lifetime cannot be read is a failed exchange.
		lifetime = readLinkedLifetime(profile, calledAt);
	} catch (err) {
		// The upstream's verdict or outage, or an answer that cannot be read,
		// not this server's: a warn. The error's cause chain can hold the
		// refused token response, so only its projection is logged.
		log.warn({ err: loggableError(err) }, "federation_callback_exchange_failed");
		res.status(502).json({
			error: "exchange_failed",
			error_description: "Token exchange with upstream IdP failed",
		});
		return null;
	}

	if (!profile.sub) {
		res.status(400).json({
			error: "invalid_profile",
			error_description: "Federation profile is missing sub claim",
		});
		return null;
	}

	const identityToken = `${provider.name}:${profile.sub}`;
	let user: Awaited<ReturnType<typeof userRepository.authenticateByToken>>;
	try {
		user = await userRepository.authenticateByToken(identityToken);
	} catch (err) {
		logStoreUnavailable(
			log,
			"federation_callback_store_unavailable",
			"user_repository",
			"authenticate_by_token",
			err,
		);
		res.status(503).json(USER_DIRECTORY_UNAVAILABLE);
		return null;
	}

	return { profile, identityToken, user, lifetime };
};
