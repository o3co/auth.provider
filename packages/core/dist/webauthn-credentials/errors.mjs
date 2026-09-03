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
 * Single discriminated-reason error class for `WebAuthnCredentialStore`
 * adapter primitives. Mirrors `RefreshTokenStorageError` and
 * `ChallengeStorageError` shape: discriminated `reason` field, native
 * ES2022 `cause` for chaining underlying adapter errors, default message
 * templated from `reason`.
 *
 * Per spec §2.3.1.
 */
export class WebAuthnCredentialStorageError extends Error {
    reason;
    constructor(opts) {
        super(opts.message ?? `WebAuthnCredentialStorageError: ${opts.reason}`, opts.cause !== undefined ? { cause: opts.cause } : undefined);
        this.name = "WebAuthnCredentialStorageError";
        this.reason = opts.reason;
    }
}
