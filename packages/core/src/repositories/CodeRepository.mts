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

import type { Code } from "./types.mjs";

/**
 * What `/authorize` hands {@link CodeRepository.createCode}: the record's own
 * fields but the code, which the repository mints.
 *
 * Derived from {@link Code} so a field added to the record is one the writer
 * has to name; every key is required so a forgotten `nonce` or `acr` cannot
 * issue a code whose id_token lacks it. Only `expiresIn` may be omitted, for
 * the repository's configured default (whole seconds).
 *
 * `expiresIn` is in seconds, a positive finite number whose end is within the
 * Date range (`isStorableLifetime`); fractions are fine, and a store keeping
 * whole milliseconds rounds up. Anything else is a `RangeError` from
 * `createCode`, and no code is stored.
 */
export type CreateCodeInput = Omit<Code, "code" | "expiresIn"> & {
	readonly expiresIn?: number | undefined;
};

export interface CodeRepository {
	/**
	 * Issue an authorization code and persist all associated data atomically.
	 * `consumeByCode` makes the code single-use; the `client_id` and
	 * `redirect_uri` in the record bind it to its client.
	 */
	createCode(params: CreateCodeInput): Promise<Code>;
	/**
	 * Retrieve a code record by the authorization code string, or `null` when
	 * none matches (the `findBy<Field>` convention of
	 * `ClientRepository.findById`).
	 */
	findByCode(code: string): Promise<Code | null>;
	/**
	 * Atomically retrieve and delete the code record. This is the sole
	 * authenticity gate for authorization code exchange. Returns null when the
	 * code is unknown or has already been consumed (replay prevention).
	 */
	consumeByCode(code: string): Promise<Code | null>;
	removeByCode(code: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// ComponentMap slot declaration
//
// `codeRepository` is produced by a composition-root-local module (e.g. the
// standalone template's `repositoriesModule`). Modules that issue or exchange
// authorization codes declare `requires: ["codeRepository"]`.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly codeRepository: CodeRepository;
	}
}
