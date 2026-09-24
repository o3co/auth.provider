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
	unavailableOf,
} from "./_responseHeaders.mjs";

/**
 * Extra request-scope facts a mechanism needs when the material is
 * presented at a **protected resource** rather than at the token endpoint.
 *
 * Passed only by {@link protectedResourceBindingMw}. The token-endpoint
 * mount ({@link tokenBindingMw}) calls `extract` with one argument, so the
 * parameter is optional and every pre-existing mechanism keeps compiling
 * and behaving exactly as before.
 *
 * The context is what makes the protected-resource profile *explicit*. The
 * alternative — letting a mechanism sniff the `Authorization` header and
 * infer which profile it is in — would make RFC 9449 §7.1's `ath`
 * requirement depend on the middleware happening to reject the wrong
 * scheme first. Two checks in different files would then have to stay
 * consistent for the binding to hold. Here the caller states the profile
 * and the mechanism enforces it.
 */
export interface TokenBindingExtractContext {
	/**
	 * The access token presented on this request, verbatim as transmitted.
	 *
	 * A mechanism whose proof binds to the access token (DPoP, via the
	 * RFC 9449 §4.2 `ath` claim) MUST verify that binding against this
	 * value. A mechanism that binds only to transport material (mTLS)
	 * ignores it.
	 *
	 * Not yet signature-verified when the mechanism runs — the endpoint
	 * downstream does that. It does not need to be: `ath` is a hash of the
	 * exact bytes presented, so a token that fails verification downstream
	 * fails the request regardless of what its `ath` matched.
	 */
	readonly boundAccessToken: string;
}

/**
 * One concrete binding mechanism (DPoP, mTLS, etc.). See Wave 2
 * Token-binding Cluster spec §4.7.
 */
export interface TokenBindingMechanism {
	readonly kind: string;
	/**
	 * `true` when the mechanism's intent signal is an explicit application-
	 * layer construction (e.g. a DPoP proof header). `false` when the
	 * signal can be an ambient transport artifact (e.g. an mTLS cert
	 * injected by a reverse proxy regardless of client intent).
	 */
	readonly intentExplicit: boolean;
	/**
	 * Return a `TokenBinding` of this mechanism's kind, `null` when the
	 * intent signal is absent, or throw a structured error when the signal
	 * is present but the proof / cert is invalid — or cannot be judged
	 * because something on the server's side failed, which the error says
	 * with `unavailable` and which is answered 503. The thrown value MAY
	 * carry a `code: string` field matching `/^[a-z][a-z0-9_]*$/` — that
	 * code is forwarded as the OAuth `error` field of the response.
	 * Errors without a snake_case `code` fall back to
	 * `invalid_<kind>_proof` so infrastructure-layer codes (e.g. Node
	 * `ECONNREFUSED`) do not leak through the public error envelope — or to
	 * `invalid_request` when the kind makes that code fall outside RFC
	 * 6749's characters. The full shape a refusal may carry is
	 * {@link TokenBindingRefusal}; its texts are sent sanitised, as
	 * `errorEnvelope` sends every description.
	 */
	extract(req: Request, ctx?: TokenBindingExtractContext): Promise<TokenBinding | null>;
}

/**
 * What a mechanism's `extract` may throw to refuse presented material — read
 * by duck type, so any `Error` with these fields qualifies (#530).
 */
export interface TokenBindingRefusal {
	/** The OAuth `error` for the answer; snake_case, or it falls back to `invalid_<kind>_proof`. */
	readonly code: string;
	/** Headers the answer carries, e.g. the `DPoP-Nonce` a client retries with. */
	readonly responseHeaders?: Readonly<Record<string, string>>;
	/**
	 * Present when the refusal is an instruction to retry rather than a
	 * verdict on the proof — RFC 9449's `use_dpop_nonce` is the one this
	 * repository ships — and the text is the answer's description. At the
	 * token endpoint the answer is `400 <code>` either way. At a protected
	 * resource an instruction is `401` with `WWW-Authenticate: <scheme>
	 * error="<code>"` and that `code` as the body's `error`; a verdict is
	 * `401 invalid_token` with `WWW-Authenticate: <scheme> error="invalid_token"`
	 * (RFC 6750 §3.1 — the mechanism's own code is logged, never sent).
	 *
	 * The mechanism states it; the dispatchers never learn a mechanism's codes
	 * (v0.13.0 audit), so a second mechanism with a retry of its own needs no
	 * change here.
	 */
	readonly retryInstruction?: string;
	/**
	 * Present when the mechanism could not reach a verdict because something
	 * on the server's side failed — a replay store that cannot be read — and
	 * the text is the answer's description. Neither a verdict on the material
	 * nor an instruction about it: the client did nothing wrong and should
	 * retry later, so both dispatchers answer `503` with `code` as the
	 * `error` (the mechanism names it; `temporarily_unavailable` is this
	 * repository's code for an outage) and no `WWW-Authenticate` challenge,
	 * because the credential is not at fault. The request is refused either
	 * way: nothing is admitted unchecked.
	 */
	readonly unavailable?: string;
}

/**
 * How `tokenBindingMw` resolves a single `TokenBinding` when multiple
 * registered mechanisms succeed on the same request.
 *
 * `"intent-explicit"` (default): explicit-intent mechanisms (DPoP) win
 * over ambient-intent mechanisms (mTLS); ≥2 explicit mechanisms
 * succeeding → 400 `invalid_request`. See spec §3.5.
 *
 * `"strict-mutual-exclusion"`: any 2+ succeeding mechanisms → 400
 * `invalid_request`. Used by deployments that want a hard mutex.
 *
 * Closed union by design — the spec went through 8 rounds of review
 * (FCoT-verified, Codex-confirmed) and intentionally bounds dispatch to
 * these two strategies as the canonical resolution policies. Adding a
 * new strategy is a core semver-minor change. Downstream consumers who
 * need a different resolution rule today should compose a thin wrapper
 * around `tokenBindingMw` that observes `req.tokenBinding` post-dispatch.
 */
export type DispatchPolicy = "intent-explicit" | "strict-mutual-exclusion";

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
 * Brand stamped on every handler {@link tokenBindingMw} returns, so boot can
 * recognise one that arrives through the legacy `grantMiddleware` slot.
 *
 * `Symbol.for` rather than a module-local symbol: the check must still work
 * when a consumer's tree ends up with two copies of this package, where a
 * local symbol would differ per copy. A missed detection is the failure mode
 * that matters here — the brand only drives a diagnostic.
 */
const TOKEN_BINDING_MW_BRAND = Symbol.for("o3co.auth-provider.tokenBindingMw");

/**
 * Whether `handler` was produced by {@link tokenBindingMw}.
 *
 * Used by `assembleApp` to detect a deployment running BOTH token-binding
 * surfaces — contributed `tokenBindingMechanisms` and a leftover v0.7
 * `grantMiddleware`-mounted `tokenBindingMw`. Exported so a custom
 * composition root that mounts `grantMiddleware` itself can run the same
 * check.
 */
export const isTokenBindingMw = (handler: unknown): boolean =>
	typeof handler === "function" &&
	// Own property, not plain access: a brand planted on a shared prototype
	// would otherwise make every function in the process match, and the
	// warning this drives would then name innocent modules.
	Object.hasOwn(handler, TOKEN_BINDING_MW_BRAND) &&
	(handler as unknown as Record<PropertyKey, unknown>)[TOKEN_BINDING_MW_BRAND] === true;

/**
 * The code a refusal without one of its own is answered under:
 * `invalid_<kind>_proof`. The kind is the contributed mechanism's, so the
 * code it makes may fall outside RFC 6749's characters (Appendix A.7); the
 * refusal is still a verdict on the client's material, so such a code is
 * answered `invalid_request` rather than `errorEnvelope`'s `server_error`.
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
					logger?.warn({ mechanism: mechanism.kind, code }, "token_binding_unavailable");
					res.status(503).json(errorEnvelope(code, unavailable));
					return;
				}
				logger?.warn({ mechanism: mechanism.kind, code }, "token_binding_proof_invalid");
				// #530: a refusal may carry headers the client needs to retry, and
				// say that it is an instruction rather than a verdict — in its own
				// words (`TokenBindingRefusal`).
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
		// All successes are ambient. With Stage 1's single ambient mechanism
		// (mTLS) `successes.length` is 1 here, but that is a property of the
		// mechanisms currently shipped, not of this code: with two ambient
		// mechanisms succeeding, the first-registered wins and the rest are
		// discarded silently — unlike the ≥2-explicit branch above, which
		// rejects.
		//
		// Whoever adds a second ambient mechanism must decide deliberately
		// whether first-wins is right for two ambient signals, or whether it
		// should reject like the explicit branch. That decision is no longer
		// guarded by this comment alone: the behavior is pinned in
		// `__tests__/tokenBinding.test.mts` ("two ambient mechanisms
		// succeeding → first-registered wins"), so changing it is an explicit
		// test edit rather than a silent behavior change (#199 M2).
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
