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
 * Single discriminated-reason error class for `DeviceCodeStore` adapters.
 * Mirrors `ChallengeStorageError` / `RefreshTokenStorageError` discipline
 * (one class, discriminated reason, no per-reason subclasses), so a caller
 * that must tell one refusal from another switches on a field rather than
 * on a message.
 */
export class DeviceCodeStoreError extends Error {
    reason;
    constructor(opts) {
        // Conditional super-arg so absent `cause` does not materialise an
        // own-property `cause` on the instance — the idiom `BootError` and
        // `ChallengeStorageError` share.
        super(opts.message ?? `DeviceCodeStoreError: ${opts.reason}`, opts.cause !== undefined ? { cause: opts.cause } : undefined);
        this.name = "DeviceCodeStoreError";
        this.reason = opts.reason;
    }
}
