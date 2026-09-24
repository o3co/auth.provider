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

import type { ExchangeTokenValidator } from "@o3co/auth-provider-core";

export type ExchangeTokenValidatorRegistryErrorReason = "duplicate" | "unknown" | "frozen";

/**
 * Error class for ExchangeTokenValidatorRegistry mutation failures.
 * Per A6+A7 §2.4.
 *
 * The `registered` snapshot lets callers see what is currently registered
 * so the diagnostic reveals the actual mental-model mismatch.
 */
export class ExchangeTokenValidatorRegistryError extends Error {
	readonly reason: ExchangeTokenValidatorRegistryErrorReason;
	readonly tokenType: string;
	readonly registered: readonly string[];

	constructor(args: {
		reason: ExchangeTokenValidatorRegistryErrorReason;
		tokenType: string;
		registered: readonly string[];
	}) {
		const detail =
			args.reason === "duplicate"
				? `token type "${args.tokenType}" is already registered`
				: args.reason === "unknown"
					? `token type "${args.tokenType}" is not registered (cannot replace)`
					: `registry is frozen; cannot mutate "${args.tokenType}"`;
		const registeredSuffix =
			args.registered.length > 0
				? `Registered: ${args.registered.join(", ")}.`
				: "Registered: (none).";
		super(`ExchangeTokenValidatorRegistryError [${args.reason}]: ${detail}. ${registeredSuffix}`);
		this.name = "ExchangeTokenValidatorRegistryError";
		this.reason = args.reason;
		this.tokenType = args.tokenType;
		this.registered = [...args.registered];
	}
}

/**
 * Registry keyed by RFC 8693 `token_type` URI. It has `get` and no `entries`,
 * so it satisfies `Pick<TokenExchangeValidatorResolver, "get">` — what the
 * grant reads — and is imported only by this package's tests, as a hand-built
 * resolver: at runtime the grant handler reads the resolver core's boot
 * planner builds from `contributes.tokenExchangeValidators`, and nothing in
 * `src/` outside the tests uses this class.
 *
 * Per A6+A7 §2.1–§2.4 (v0.5.0 unified contract):
 * - `register(name, validator)` throws on duplicate REGARDLESS of freeze
 *   state (was: silent overwrite pre-freeze in v0.4.x).
 * - `replace(name, validator)` is the explicit override path.
 * - `freeze()` is the activation boundary — after freeze, register and
 *   replace throw reason="frozen"; get continues to work.
 */
export class ExchangeTokenValidatorRegistry {
	private validators = new Map<string, ExchangeTokenValidator>();
	private frozen = false;

	register(tokenType: string, validator: ExchangeTokenValidator): void {
		if (this.frozen) {
			throw new ExchangeTokenValidatorRegistryError({
				reason: "frozen",
				tokenType,
				registered: [...this.validators.keys()],
			});
		}
		if (this.validators.has(tokenType)) {
			throw new ExchangeTokenValidatorRegistryError({
				reason: "duplicate",
				tokenType,
				registered: [...this.validators.keys()],
			});
		}
		this.validators.set(tokenType, validator);
	}

	replace(tokenType: string, validator: ExchangeTokenValidator): void {
		if (this.frozen) {
			throw new ExchangeTokenValidatorRegistryError({
				reason: "frozen",
				tokenType,
				registered: [...this.validators.keys()],
			});
		}
		if (!this.validators.has(tokenType)) {
			throw new ExchangeTokenValidatorRegistryError({
				reason: "unknown",
				tokenType,
				registered: [...this.validators.keys()],
			});
		}
		this.validators.set(tokenType, validator);
	}

	get(tokenType: string): ExchangeTokenValidator | undefined {
		return this.validators.get(tokenType);
	}

	/**
	 * Seal the registry. Idempotent: calling freeze() on an already-frozen
	 * registry is a no-op.
	 */
	freeze(): void {
		this.frozen = true;
	}
}
