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
import { errorEnvelope } from "../errors/envelope.mjs";
import type { TokenBinding } from "../grants/tokenBinding.mjs";
import type { Logger } from "../logging/Logger.mjs";

import "./express.mjs"; // ensure ambient Express.Request augmentation is loaded

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
	 * is present but the proof / cert is invalid. The thrown value MAY
	 * carry a `code: string` field matching `/^[a-z][a-z0-9_]*$/` — that
	 * code is forwarded as the OAuth `error` field of the 400 response.
	 * Errors without a snake_case `code` fall back to
	 * `invalid_<kind>_proof` so infrastructure-layer codes (e.g. Node
	 * `ECONNREFUSED`) do not leak through the public error envelope.
	 */
	extract(req: Request, ctx?: TokenBindingExtractContext): Promise<TokenBinding | null>;
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

const OAUTH_ERROR_CODE_PATTERN = /^[a-z][a-z0-9_]*$/;

const hasOAuthErrorCode = (err: unknown): err is { code: string } =>
	typeof err === "object" &&
	err !== null &&
	"code" in err &&
	typeof (err as { code: unknown }).code === "string" &&
	OAUTH_ERROR_CODE_PATTERN.test((err as { code: string }).code);

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
				const code = hasOAuthErrorCode(err) ? err.code : `invalid_${mechanism.kind}_proof`;
				logger?.warn({ mechanism: mechanism.kind, code }, "token_binding_proof_invalid");
				res
					.status(400)
					.json(errorEnvelope(code, `${mechanism.kind} mechanism rejected the presented material`));
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
