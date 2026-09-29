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
 */
import type { Request, RequestHandler } from "express";
import { errorEnvelope, isWellFormedErrorCode } from "../errors/envelope.mjs";
import type { TokenBinding } from "../grants/tokenBinding.mjs";
import type { Logger } from "../logging/Logger.mjs";

import "./express.mjs"; // ensure ambient Express.Request augmentation is loaded
import {
	applyResponseHeaders,
	oauthErrorCodeOf,
	retryInstructionOf,
	unavailableLogFields,
	unavailableOf,
	verdictLogFields,
} from "./_responseHeaders.mjs";

/**
 * Request-scope facts a mechanism needs when material is presented at a
 * **protected resource** rather than at the token endpoint. Passed only by
 * {@link protectedResourceBindingMw}; {@link tokenBindingMw} calls `extract`
 * without it.
 *
 * It makes the protected-resource profile explicit. A mechanism that sniffed
 * the `Authorization` header instead would make RFC 9449 §7.1's `ath`
 * requirement depend on the middleware rejecting the wrong scheme first: two
 * checks in different files that must stay consistent.
 */
export interface TokenBindingExtractContext {
	/**
	 * The access token presented on this request, verbatim. A mechanism whose
	 * proof binds to it (DPoP, via the RFC 9449 §4.2 `ath` claim) MUST verify
	 * against it; one that binds only to transport material (mTLS) ignores it.
	 * It is not yet signature-verified, and need not be: `ath` hashes the exact
	 * bytes, so a token that fails verification downstream fails the request.
	 */
	readonly boundAccessToken: string;
}

/**
 * One concrete binding mechanism (DPoP, mTLS, etc.). See ADR
 * 2026-05-20-token-binding-first-class-abstraction.
 */
export interface TokenBindingMechanism {
	readonly kind: string;
	/**
	 * `true` when the intent signal is an explicit application-layer construct
	 * (a DPoP proof header); `false` when it can be an ambient transport
	 * artifact (an mTLS cert a reverse proxy injects regardless of intent).
	 */
	readonly intentExplicit: boolean;
	/**
	 * Return a `TokenBinding` of this mechanism's kind, `null` when the intent
	 * signal is absent, or throw a {@link TokenBindingRefusal} when the signal is
	 * present but the proof or cert is invalid, or cannot be judged because of a
	 * server-side failure (`unavailable`, answered 503). A thrown `code` matching
	 * `/^[a-z][a-z0-9_]*$/` becomes the OAuth `error`; otherwise it falls back to
	 * `invalid_<kind>_proof` (or `invalid_request` when that falls outside RFC
	 * 6749's characters), so infrastructure codes such as `ECONNREFUSED` never
	 * leak. Texts are sent sanitised, as `errorEnvelope` sends every description.
	 */
	extract(req: Request, ctx?: TokenBindingExtractContext): Promise<TokenBinding | null>;
}

/**
 * What a mechanism's `extract` may throw to refuse presented material. Read by
 * duck type, so any `Error` with these fields qualifies.
 */
export interface TokenBindingRefusal {
	/** The OAuth `error` for the answer; snake_case, or it falls back to `invalid_<kind>_proof`. */
	readonly code: string;
	/** Headers the answer carries, e.g. the `DPoP-Nonce` a client retries with. */
	readonly responseHeaders?: Readonly<Record<string, string>>;
	/**
	 * Present when the refusal is an instruction to retry rather than a verdict
	 * (RFC 9449's `use_dpop_nonce` is the one shipped); the text is the answer's
	 * description. At the token endpoint the answer is `400 <code>` either way.
	 * At a protected resource an instruction is `401` with `WWW-Authenticate:
	 * <scheme> error="<code>"`; a verdict is `401 invalid_token` (RFC 6750 §3.1;
	 * the mechanism's own code is logged, never sent). The mechanism states it,
	 * so the dispatchers never need to know a mechanism's codes.
	 */
	readonly retryInstruction?: string;
	/**
	 * Present when a server-side failure (such as an unreadable replay store)
	 * stopped the verdict; the text is the answer's description. The client did
	 * nothing wrong, so both dispatchers answer `503` with `code` as the `error`
	 * (`temporarily_unavailable` is this repository's outage code) and no
	 * `WWW-Authenticate` challenge. The request is still refused: nothing is
	 * admitted unchecked.
	 */
	readonly unavailable?: string;
	/**
	 * With `unavailable`: the failure that stopped the verdict. The dispatcher
	 * that answers the `503` writes the one error-level line
	 * (`token_binding_unavailable`, `protected_resource_binding_unavailable`)
	 * with this cause's projection, so a mechanism should not log the outage
	 * itself. Optional.
	 *
	 * On a verdict: the error that made the mechanism refuse (a parser's, a
	 * library's), kept here rather than copied into the message; the verdict
	 * line carries it inside the refusal's projection.
	 */
	readonly cause?: unknown;
	/**
	 * The mechanism's own name for the refusal (`replay_store_unavailable`,
	 * mTLS's `malformed_header`), logged beside the `code`. Lowercase words
	 * joined by `_` or `-`; anything else is left off the line. Never sent.
	 */
	readonly reason?: string;
}

/**
 * How `tokenBindingMw` picks one `TokenBinding` when several mechanisms
 * succeed on a request.
 *
 * `"intent-explicit"` (default): explicit-intent mechanisms (DPoP) win over
 * ambient ones (mTLS); two or more explicit successes → 400 `invalid_request`.
 *
 * `"strict-mutual-exclusion"`: two or more successes of any kind → 400
 * `invalid_request`.
 *
 * Closed union by design (ADR 2026-05-20-token-binding-first-class-abstraction);
 * adding a strategy is a core semver-minor change. For another rule, wrap
 * `tokenBindingMw` and inspect `req.tokenBinding` after it runs.
 */
export type DispatchPolicy = "intent-explicit" | "strict-mutual-exclusion";

/**
 * Settings across every mechanism at core's token-binding extension point, from
 * the `oauth.tokenBinding` section. They are core's, as the extension point is,
 * and no slot carries them (not the oauth module's `oauthTokenSettings`, though
 * the section sits in `oauth {}`).
 */
export interface TokenBindingSettings {
	/**
	 * `dispatch-policy`: how `tokenBindingMw` arbitrates between contributed
	 * `tokenBindingMechanisms`. `intent-explicit` unless the section says
	 * `strict-mutual-exclusion`.
	 */
	readonly dispatchPolicy: DispatchPolicy;
	/**
	 * `bindConfidentialClientRefreshTokens`: whether a grant binds a
	 * confidential client's refresh token to the key or certificate presented,
	 * as it always binds a public client's. `true` only when set to `true`.
	 */
	readonly bindConfidentialClientRefreshTokens: boolean;
}

/**
 * The token-binding settings a configuration declares, frozen: the one reader
 * of `oauth.tokenBinding`, for boot (the dispatch policy) and every grant that
 * mints a refresh token (the confidential-client rule). Takes any value, as
 * boot holds the configuration.
 */
export function resolveTokenBindingSettings(config: unknown): TokenBindingSettings {
	const section = (
		config as {
			oauth?: {
				tokenBinding?: {
					"dispatch-policy"?: unknown;
					bindConfidentialClientRefreshTokens?: unknown;
				};
			};
		} | null
	)?.oauth?.tokenBinding;
	return Object.freeze({
		dispatchPolicy:
			section?.["dispatch-policy"] === "strict-mutual-exclusion"
				? "strict-mutual-exclusion"
				: "intent-explicit",
		bindConfidentialClientRefreshTokens: section?.bindConfidentialClientRefreshTokens === true,
	});
}

export interface TokenBindingMiddlewareOptions {
	readonly mechanisms: readonly TokenBindingMechanism[];
	readonly dispatchPolicy: DispatchPolicy;
	readonly logger?: Logger;
}

interface MechanismResult {
	readonly mechanism: TokenBindingMechanism;
	readonly binding: TokenBinding;
}

/**
 * Brand on every handler {@link tokenBindingMw} returns, so boot can recognise
 * one arriving through the legacy `grantMiddleware` slot. `Symbol.for` so the
 * check still works when a consumer's tree holds two copies of this package.
 */
const TOKEN_BINDING_MW_BRAND = Symbol.for("o3co.auth-provider.tokenBindingMw");

/**
 * Whether `handler` was produced by {@link tokenBindingMw}. `assembleApp` uses
 * it to detect a deployment running both contributed `tokenBindingMechanisms`
 * and a `grantMiddleware`-mounted `tokenBindingMw`; exported for composition
 * roots that mount `grantMiddleware` themselves.
 */
export const isTokenBindingMw = (handler: unknown): boolean =>
	typeof handler === "function" &&
	// Own property, not plain access: a brand planted on a shared prototype
	// would otherwise make every function in the process match, and the
	// warning this drives would then name innocent modules.
	Object.hasOwn(handler, TOKEN_BINDING_MW_BRAND) &&
	(handler as unknown as Record<PropertyKey, unknown>)[TOKEN_BINDING_MW_BRAND] === true;

/**
 * The code for a refusal without its own: `invalid_<kind>_proof`. A contributed
 * kind may put that outside RFC 6749's characters (Appendix A.7); the refusal
 * is still a verdict on the client's material, so it is then `invalid_request`
 * rather than `errorEnvelope`'s `server_error`.
 */
const refusalCodeFor = (kind: string): string => {
	const code = `invalid_${kind}_proof`;
	return isWellFormedErrorCode(code) ? code : "invalid_request";
};

export const tokenBindingMw = ({
	mechanisms,
	dispatchPolicy,
	logger,
}: TokenBindingMiddlewareOptions): RequestHandler => {
	const handler: RequestHandler = async (req, res, next) => {
		// Step 1 — validate all presented binding material.
		const successes: MechanismResult[] = [];
		for (const mechanism of mechanisms) {
			let binding: TokenBinding | null;
			try {
				binding = await mechanism.extract(req);
			} catch (err) {
				const code = oauthErrorCodeOf(err) ?? refusalCodeFor(mechanism.kind);
				// An outage the mechanism reports is not a refused proof: 503, and
				// logged under its own event so the two are never counted as one.
				const unavailable = unavailableOf(err);
				if (unavailable !== undefined) {
					// This layer answers the 503, so it owns the outage's one line.
					logger?.error(
						{ mechanism: mechanism.kind, code, ...unavailableLogFields(err) },
						"token_binding_unavailable",
					);
					res.status(503).json(errorEnvelope(code, unavailable));
					return;
				}
				// A verdict on the material: one warn line (`verdictLogFields`).
				logger?.warn(
					{ mechanism: mechanism.kind, code, ...verdictLogFields(err) },
					"token_binding_proof_invalid",
				);
				// A refusal may carry headers the client needs to retry, and say in
				// its own words that it is an instruction, not a verdict.
				applyResponseHeaders(res, err);
				res
					.status(400)
					.json(
						errorEnvelope(
							code,
							retryInstructionOf(err) ??
								`${mechanism.kind} mechanism rejected the presented material`,
						),
					);
				return;
			}
			if (binding !== null) {
				successes.push({ mechanism, binding });
			}
		}

		// Step 2 — resolve binding by dispatch policy.
		const [firstSuccess] = successes;
		if (!firstSuccess) {
			next();
			return;
		}

		if (dispatchPolicy === "strict-mutual-exclusion") {
			if (successes.length > 1) {
				const kinds = successes.map((s) => s.mechanism.kind).join(", ");
				res
					.status(400)
					.json(
						errorEnvelope(
							"invalid_request",
							`multiple token-binding mechanisms succeeded (${kinds}); strict-mutual-exclusion forbids any overlap`,
						),
					);
				return;
			}
			applyResponseHeaders(res, firstSuccess.binding);
			req.tokenBinding = firstSuccess.binding;
			next();
			return;
		}

		// dispatchPolicy === "intent-explicit"
		const explicit = successes.filter((s) => s.mechanism.intentExplicit);
		if (explicit.length >= 2) {
			const kinds = explicit.map((s) => s.mechanism.kind).join(", ");
			res
				.status(400)
				.json(
					errorEnvelope(
						"invalid_request",
						`multiple explicit-intent token-binding mechanisms succeeded (${kinds})`,
					),
				);
			return;
		}
		const [firstExplicit] = explicit;
		if (firstExplicit) {
			applyResponseHeaders(res, firstExplicit.binding);
			req.tokenBinding = firstExplicit.binding;
			next();
			return;
		}
		// All successes are ambient. With two ambient mechanisms succeeding, the
		// first-registered wins and the rest are silently discarded, unlike the
		// explicit branch, which rejects. Only mTLS ships today; whoever adds a
		// second ambient mechanism must decide whether first-wins is right. The
		// behaviour is pinned in `__tests__/tokenBinding.test.mts`.
		applyResponseHeaders(res, firstSuccess.binding);
		req.tokenBinding = firstSuccess.binding;
		next();
	};
	// Non-enumerable so the brand never shows up in middleware introspection,
	// logging, or a structural clone of the handler.
	Object.defineProperty(handler, TOKEN_BINDING_MW_BRAND, {
		value: true,
		enumerable: false,
		writable: false,
		configurable: false,
	});
	return handler;
};
