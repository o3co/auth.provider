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
	 * is present but the proof / cert is invalid.
	 */
	extract(req: Request): Promise<TokenBinding | null>;
}

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

const isLikelyDPoPProofError = (err: unknown): boolean =>
	typeof err === "object" &&
	err !== null &&
	"code" in err &&
	typeof (err as { code: unknown }).code === "string";

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
				const code = isLikelyDPoPProofError(err)
					? (err as { code: string }).code
					: `invalid_${mechanism.kind}_proof`;
				logger?.warn({ mechanism: mechanism.kind, code }, "token_binding_proof_invalid");
				res.status(400).json({
					error: code,
					error_description: `${mechanism.kind} mechanism rejected the presented material`,
				});
				return;
			}
			if (binding !== null) {
				successes.push({ mechanism, binding });
			}
		}

		// Step 2 — resolve binding by dispatch policy.
		if (successes.length === 0) {
			next();
			return;
		}

		if (dispatchPolicy === "strict-mutual-exclusion") {
			if (successes.length > 1) {
				const kinds = successes.map((s) => s.mechanism.kind).join(", ");
				res.status(400).json({
					error: "invalid_request",
					error_description: `multiple token-binding mechanisms succeeded (${kinds}); strict-mutual-exclusion forbids any overlap`,
				});
				return;
			}
			req.tokenBinding = successes[0]?.binding;
			next();
			return;
		}

		// dispatchPolicy === "intent-explicit"
		const explicit = successes.filter((s) => s.mechanism.intentExplicit);
		if (explicit.length >= 2) {
			const kinds = explicit.map((s) => s.mechanism.kind).join(", ");
			res.status(400).json({
				error: "invalid_request",
				error_description: `multiple explicit-intent token-binding mechanisms succeeded (${kinds})`,
			});
			return;
		}
		if (explicit.length === 1) {
			req.tokenBinding = explicit[0]?.binding;
			next();
			return;
		}
		// All successes are ambient. Stage 1 has exactly one ambient
		// mechanism (mTLS), so successes.length is at most 1 here in
		// Stage 1. The first-wins rule is structurally unique; Stage 2+
		// must revisit if a second ambient mechanism is added.
		req.tokenBinding = successes[0]?.binding;
		next();
	};
};
