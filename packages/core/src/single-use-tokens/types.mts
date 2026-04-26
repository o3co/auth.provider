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

import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";

export type SingleUseConsumeOutcome =
	| { readonly outcome: "consumed" }
	| { readonly outcome: "unknown" }
	| { readonly outcome: "replayed" };

export type SingleUseMarkSeenOutcome =
	| { readonly outcome: "fresh" }
	| { readonly outcome: "replayed" };

export interface SingleUseTokenStoreBase {
	readonly kind: string;

	/**
	 * Register a server-issued single-use token (e.g. WebAuthn challenge).
	 *
	 * Throws SingleUseTokenError({ reason: "duplicate" }) when (scope, key)
	 * has any non-expired record (issued OR consumed) — re-issuing on top of
	 * a consumed record would defeat replay detection.
	 *
	 * Throws SingleUseTokenError({ reason: "expired-at-issue" }) when
	 * expiresAt <= now at call time, before any state mutation.
	 */
	issue(scope: string, key: string, expiresAt: Date): Promise<void>;

	/**
	 * Atomically consume a previously-issued single-use token. Concurrent
	 * consume calls for the same (scope, key) MUST yield exactly one
	 * `consumed` and the rest `replayed` — never two `consumed`, never
	 * `unknown` for an issued-then-consumed token until expiresAt.
	 */
	consume(scope: string, key: string): Promise<SingleUseConsumeOutcome>;

	/**
	 * Atomically check-and-record a client-supplied identifier (e.g. JWT jti)
	 * for replay protection. Returns `fresh` on first observation within the
	 * TTL window, `replayed` on subsequent calls.
	 *
	 * Throws SingleUseTokenError({ reason: "expired-at-issue" }) when
	 * expiresAt <= now.
	 *
	 * markSeen and consume MUST NOT share a key namespace — caller's
	 * responsibility to keep `scope` disjoint between the two operations.
	 */
	markSeen(scope: string, key: string, expiresAt: Date): Promise<SingleUseMarkSeenOutcome>;
}

export type SingleUseTokenStoreFactory = AdapterFactory<SingleUseTokenStoreBase>;

/**
 * Structured error type for `issue` / `markSeen` rejections.
 *
 * - `duplicate`: (scope, key) already has a non-expired record (issued OR consumed).
 * - `expired-at-issue`: expiresAt <= now at call time.
 *
 * Adapters MUST throw this exact class so consumers can branch on `reason`.
 * Future variants are additive only.
 */
export class SingleUseTokenError extends Error {
	readonly reason: "duplicate" | "expired-at-issue";

	constructor(opts: { reason: "duplicate" | "expired-at-issue"; message?: string }) {
		super(opts.message ?? `SingleUseTokenError: ${opts.reason}`);
		this.name = "SingleUseTokenError";
		this.reason = opts.reason;
	}
}
