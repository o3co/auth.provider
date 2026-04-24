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

import type { ExchangeTokenValidator } from "./types.mjs";

/**
 * Registry keyed by RFC 8693 `token_type` URI. Used by the Token Exchange
 * grant handler to dispatch `subject_token` / `actor_token` validation.
 *
 * Mutability contract:
 *   - Before `freeze()`: `register()` is idempotent; later registrations
 *     overwrite earlier ones (useful during application wire-up).
 *   - After `freeze()`: `register()` throws; `get()` continues to work.
 *
 * The GrantModule calls `freeze()` at `addModule` time, so once the grant
 * handler is active the registry cannot be mutated — this prevents a
 * consumer reference from silently replacing the built-in self-issued
 * access_token validator after startup.
 */
export class ExchangeTokenValidatorRegistry {
	private validators = new Map<string, ExchangeTokenValidator>();
	private frozen = false;

	register(tokenType: string, validator: ExchangeTokenValidator): void {
		if (this.frozen) {
			throw new Error(
				`ExchangeTokenValidatorRegistry is frozen; cannot register "${tokenType}" after freeze()`,
			);
		}
		this.validators.set(tokenType, validator);
	}

	get(tokenType: string): ExchangeTokenValidator | undefined {
		return this.validators.get(tokenType);
	}

	/**
	 * Seal the registry. After freeze(), `register()` throws. Idempotent:
	 * calling freeze() on an already-frozen registry is a no-op.
	 */
	freeze(): void {
		this.frozen = true;
	}
}
