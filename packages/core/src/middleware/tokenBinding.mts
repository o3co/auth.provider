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
	extract(req: Request): Promise<TokenBinding | null>;
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

export const tokenBindingMw = ({
	mechanisms,
	dispatchPolicy,
	logger,
}: TokenBindingMiddlewareOptions): RequestHandler => {
	return async (req, res, next) => {
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
		// All successes are ambient. Stage 1 has exactly one ambient
		// mechanism (mTLS), so `successes.length` is provably 1 here
		// (and `firstSuccess` is its single element). Stage 2+ adding a
		// second ambient mechanism must revisit this first-wins rule —
		// a corresponding test for multi-ambient is intentionally
		// deferred until that second mechanism exists.
		req.tokenBinding = firstSuccess.binding;
		next();
	};
};
